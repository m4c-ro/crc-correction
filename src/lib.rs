//!# CRC Correction
//!
//!Attempt to correct corrupted data with a CRC.
//!
//!Uses the [crc](https://crates.io/crates/crc) crate for the CRC implementation and provides
//!correction on top of that.
#![no_std]
#![forbid(missing_docs)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]

use core::fmt::{Debug, Display, Formatter};
use core::result::Result;

use crc::{Crc, Table};
use sort_const::const_quicksort;

/// CRC Corrector
///
/// Associated const 'CrcCorrector::L' refers to message length in bits including an appended CRC
pub struct CrcCorrector<const L: usize> {
    crc: Crc<u32, Table<1>>,
    // CRC of an empty message of bit length L
    zero_crc: u32,
    // List of CRC's computed for messages of length L (bits) with each entry at index i in the
    // table corresponding to a message with the bit at i set to 1 and all other bits to 0.
    table: [u32; L],
}

impl<const L: usize> CrcCorrector<L> {
    /// Construct CRC Corrector, including lookup table, for a given CRC algorithm and message
    /// length
    pub const fn new(crc: Crc<u32, Table<1>>) -> Self {
        // Ensure table length is within bounds
        let mut table = [0u32; L];
        let mut sorted_table = [0u32; L];
        if table.len() % 8 != 0 {
            panic!("CrcCorrector message length must be a multiple of 8!");
        }
        if table.len() > (u32::MAX - 32) as usize {
            panic!(
                "CrcCorrector message length is too large to compute a correction lookup table!"
            );
        }

        // Hack to work around no const-generic-exprs
        let msg_arr = &mut [0u8; L];
        let msg = msg_arr.split_at_mut(table.len() >> 3).0;

        let zero_crc = crc.checksum(msg);

        // Generate lookup table for given message length and CRC algorithm
        let mut i = 0;
        while i < L {
            let byte = i >> 3;
            let bit = (1 << (i & 7)) as u8;

            msg[byte] = bit;

            let csum = crc.checksum(msg);
            table[i] = csum;
            sorted_table[i] = csum;

            msg[byte] = 0;
            i += 1;
        }

        // Verify all table entries are unique, ensuring that this CrcCorrection instance is valid
        // for single bit errors
        let mut i = 0;
        const_quicksort!(sorted_table);
        while i < (sorted_table.len() - 1) {
            if sorted_table[i] == sorted_table[i + 1] {
                panic!(
                    "Provided CRC algorithm is insufficient for single-bit error correction. Either increase the CRC bit length or choose a different polynomial"
                );
            }
            i += 1;
        }

        Self {
            crc,
            zero_crc,
            table,
        }
    }

    /// Correct message with a CRC appended in the last 32 bits. This is able to correct a single
    /// bit of corruption in either the provided message or the provided CRC. This method mutates
    /// the message to correct corruption but will not mutate it if correction fails.
    pub fn correct(&self, data: &mut [u8]) -> Result<Correction, Error> {
        if data.len() <= 4 {
            return Err(Error::MissingAppendedCRC);
        }

        if data.len() << 3 > self.table.len() {
            return Err(Error::DataTooLong);
        }

        // If crc(data + padding + crc) = zero of an all zero's message then the data is fine
        let crc2 = self.crc2(data);
        if crc2 == self.zero_crc {
            return Err(Error::NoError);
        }

        // Find this CRC in the table
        let mut i = 0;
        let mut error_bit = None;
        while i < self.table.len() {
            if crc2 == self.table[i] {
                error_bit = Some(i as u32);
                break;
            }
            i += 1;
        }

        // If the CRC isn't in the table then the data is corrupted in more than one bit, and we
        // can't correct it with this algorithm.
        let Some(mut error_bit) = error_bit else {
            return Err(Error::MoreThanOneBitCorrupted);
        };

        // If the error bit is in the CRC and we've reflected the CRC in `crc2` then we need to
        // reflect it back to correct the right bit
        let msg_bit_len = ((data.len() - 4) << 3) as u32;
        if error_bit >= msg_bit_len && self.crc.algorithm.refout {
            let mut crc_error_bit = error_bit - msg_bit_len;
            match crc_error_bit >> 3 {
                0 => crc_error_bit += 24,
                1 => crc_error_bit += 8,
                2 => crc_error_bit -= 8,
                3 => crc_error_bit -= 24,
                _ => unreachable!(),
            }
            error_bit = crc_error_bit + msg_bit_len;
        }

        // Flip erroneous bit
        let offset_byte = (error_bit >> 3) as usize;
        let offset_bit = (1 << (error_bit & 7)) as u8;
        data[offset_byte] ^= offset_bit;

        // Check if the correction worked with another CRC of data + appended CRC
        let crc2 = self.crc2(&data);
        if crc2 != self.zero_crc {
            // Correction failed, flip back the changed bit in input before returning
            data[offset_byte] ^= offset_bit;
            return Err(Error::CorrectionFailed);
        }

        // If error bit is bigger than data bit length the error is in the CRC
        if error_bit >= msg_bit_len {
            Ok(Correction::CRC {
                error_bit: error_bit - msg_bit_len,
            })
        } else {
            Ok(Correction::Data { error_bit })
        }
    }

    /// Calculate CRC of data + appended CRC
    fn crc2(&self, data: &[u8]) -> u32 {
        // Before calculating the CRC of (data + crc) we need to
        //  1. Modify the CRC so that it's not reflected or XOR'd
        //  2. Insert padding zeros to extend the message to length L

        // Reflect and XOR the CRC if the algorithm requires it
        let len = data.len();
        let crc_bytes = [data[len - 4], data[len - 3], data[len - 2], data[len - 1]];
        let mut crc;
        if self.crc.algorithm.refout {
            crc = u32::from_le_bytes(crc_bytes)
        } else {
            crc = u32::from_be_bytes(crc_bytes)
        }
        crc ^= self.crc.algorithm.xorout;
        let crc_bytes = crc.to_be_bytes();

        let mut digest = self.crc.digest_with_initial(0);
        digest.update(&data[..len - 4]);
        digest.update(&crc_bytes);

        // Extend data with zeros to bit length L
        let data_bit_len = data.len() << 3;
        let mut remaining_bits = self.table.len() - data_bit_len;
        while remaining_bits >= 128 {
            digest.update(&[0u8; 16]);
            remaining_bits -= 128
        }
        while remaining_bits > 0 {
            digest.update(&[0u8; 1]);
            remaining_bits -= 8;
        }

        digest.finalize()
    }
}

/// Type of correction applied to the data
#[derive(Debug, PartialEq, Eq)]
pub enum Correction {
    /// A single bit in CRC was corrupted
    CRC {
        /// Bit offset within the CRC
        error_bit: u32,
    },
    /// A single bit was the data was corrupted
    Data {
        /// Bit offset within the data
        error_bit: u32,
    },
}

/// CRC Correction Error
#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    /// No corruption was found in the provided data. This is an error because the expectation when
    /// using `crc_correction::correct_crc32` is that the provided data has been corrupted.
    NoError,
    /// We currently only support error correction for one bit. This error indicates that more than
    /// one bit was corrupted in the provided data.
    MoreThanOneBitCorrupted,
    /// Provided data is too long for the `CrcCorrector`. Make sure to set `CrcCorrector::L`
    /// and `crc::Algorithm` appropriately.
    DataTooLong,
    /// Expected CRC to be appended in last four bytes of data, but the provided message is too
    /// short.
    MissingAppendedCRC,
    /// Failed to correct the data.
    CorrectionFailed,
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter) -> Result<(), core::fmt::Error> {
        match self {
            Self::NoError => {
                write!(f, "No error, CRC matches expected")
            }
            Self::MoreThanOneBitCorrupted => {
                write!(
                    f,
                    "Unable to correct data with CRC, more than one bit has been corrupted"
                )
            }
            Self::DataTooLong => {
                write!(
                    f,
                    "Message is too large for CRC correction with this CRC corrector"
                )
            }
            Self::MissingAppendedCRC => {
                write!(f, "Message is too small to contain appended CRC")
            }
            Self::CorrectionFailed => {
                write!(f, "Unable to correct data with CRC")
            }
        }
    }
}

impl core::error::Error for Error {}
