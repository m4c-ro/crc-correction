//! # CRC Correction
//!
//! Attempt to correct corrupted data with a CRC. This library is able to correct single bit errors in
//! data so long as the CRC algorithm is known and the data is less than a pre-defined length. Single
//! bit errors in the CRC are also fixable.
//!
//! Uses the [crc](https://crates.io/crates/crc) crate for the actual CRC implementations. We support
//! all 16, 32 and 64 bit CRC algorithms from [crc](https://crates.io/crates/crc).
//!
//! ### Example
//!
//! ```rust
//! use crc::{Crc, Table, CRC_32_CKSUM};
//! use crc_correction::{CrcCorrector, Error};
//!
//! // Maximum message length, in bits, including CRC bits.
//! const MAX_MSG_LEN: usize = 256;
//!
//! // CRC instance to use
//! const CRC: Crc<u32, Table<1>> =
//!     Crc::<u32, Table<1>>::new(&CRC_32_CKSUM);
//!
//! // Corrector instance. Note that this generates a lookup
//! // table for correction at compile time, so runtime
//! // checks are faster.
//! const CORRECTOR: CrcCorrector::<MAX_MSG_LEN, u32> =
//!     CrcCorrector::<MAX_MSG_LEN, u32>::new(CRC);
//!
//! fn main() {
//!     // Note that the length leaves 4 bytes room for CRC
//!     // compared to MAX_MSG_LEN
//!     let mut msg = [123u8; 28];
//!     let crc = 0u32;
//!
//!     let result = CORRECTOR.correct(&mut msg, crc);
//!
//!     // Since we didn't calculate a CRC in this example
//!     assert_eq!(result, Err(Error::MoreThanOneBitCorrupted));
//! }
//! ```
//!
//! ### Compile Times
//!
//! A lookup table is generated containing a CRC for every bit in the desired maximum message length.
//! This can take some time to generate. It is recommended to use another form of error correction for
//! very long messages. If the compiler complains about very long constant evaluation you may generate
//! the table at runtime by initializing `CrcCorrector` on the heap, or disable the compiler lint as
//! follows:
//!
//! ```rust
//! use crc::{Crc, Table, CRC_32_CKSUM};
//! use crc_correction::CrcCorrector;
//!
//! const MAX_MSG_LEN: usize = 256;
//! const CRC: Crc<u32, Table<1>> =
//!     Crc::<u32, Table<1>>::new(&CRC_32_CKSUM);
//!
//! // Allow the corrector table generation to take a long
//! // time during compilation
//! #[allow(long_running_const_eval)]
//! const CORRECTOR: CrcCorrector::<MAX_MSG_LEN, u32> =
//!     CrcCorrector::<MAX_MSG_LEN, u32>::new(CRC);
//! ```
#![no_std]
#![forbid(missing_docs)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![allow(clippy::cast_possible_truncation)]

use core::fmt::{Debug, Display, Formatter};
use core::result::Result;

use crc::{Crc, Table, Width};
use sort_const::const_quicksort;

/// CRC Corrector
///
/// Associated const `CrcCorrector::L` refers to message length in bits including an appended CRC
#[derive(Clone)]
pub struct CrcCorrector<const L: usize, W: Width> {
    crc: Crc<W, Table<1>>,
    // CRC of an empty message of bit length L
    zero_crc: W,
    // List of CRC's computed for messages of length L (bits) with each entry at index i in the
    // table corresponding to a message with the bit at i set to 1 and all other bits to 0.
    table: [W; L],
}

macro_rules! crc_reflect {
    ($crc_error_bit:tt, u16) => {
        match $crc_error_bit >> 3 {
            0 => $crc_error_bit += 8,
            1 => $crc_error_bit -= 8,
            _ => unreachable!(),
        }
    };
    ($crc_error_bit:tt, u32) => {
        match $crc_error_bit >> 3 {
            0 => $crc_error_bit += 24,
            1 => $crc_error_bit += 8,
            2 => $crc_error_bit -= 8,
            3 => $crc_error_bit -= 24,
            _ => unreachable!(),
        }
    };
    ($crc_error_bit:tt, u64) => {
        match $crc_error_bit >> 3 {
            0 => $crc_error_bit += 56,
            1 => $crc_error_bit += 40,
            2 => $crc_error_bit += 24,
            3 => $crc_error_bit += 8,
            4 => $crc_error_bit -= 8,
            5 => $crc_error_bit -= 24,
            6 => $crc_error_bit -= 40,
            7 => $crc_error_bit -= 56,
            _ => unreachable!(),
        }
    };
}

macro_rules! corrector_impl {
    ($uint:tt) => {
        impl<const L: usize> CrcCorrector<L, $uint> {
            /// Construct CRC Corrector, including lookup table, for a given CRC algorithm and message
            /// length.
            ///
            /// # Panics
            /// This function will panic if
            ///
            /// * The message length is not a multiple of 8. (We expect byte data)
            /// * The requested table length is too large
            /// * The CRC algorithm cannot reliably perform single bit correction with the required
            ///   message length
            ///
            /// In the last case the problem is similar to a hash collision. Either choose a longer
            /// CRC (64 bit vs 32 bit vs 16 bit) or a different algorithm. Ultimately there is a
            /// limit to the message length a CRC can correct errors for.
            #[must_use]
            pub const fn new(crc: Crc<$uint, Table<1>>) -> Self {
                // Ensure table length is within bounds
                let mut table = [$uint::MIN; L];
                if table.len() % 8 != 0 {
                    panic!("CrcCorrector message length must be a multiple of 8!");
                }
                if table.len() > ($uint::MAX - ($uint::BITS as $uint)) as usize {
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
                    let bit = 1u8 << (i & 7) as u8;

                    msg[byte] = bit;

                    let csum = crc.checksum(msg);
                    table[i] = csum;

                    msg[byte] = 0;
                    i += 1;
                }

                // Verify all table entries are unique, ensuring that this CrcCorrection instance is valid
                // for single bit errors
                let mut i = 0;
                let sorted_table: &[$uint] = &const_quicksort!(table);
                while i < (sorted_table.len() - 1) {
                    if sorted_table[i] == sorted_table[i + 1] || sorted_table[i] == zero_crc {
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

            /// Correct message with a single bit of corruption in either the provided message or
            /// the provided CRC. This method mutates the message to correct corruption but will
            /// not mutate it if correction fails.
            ///
            /// If a correction is applied the CRC is validated again to ensure that the integrity
            /// of the data is okay. This isn't strictly necessary, but guards against any bugs
            /// which would incorrectly 'correct' data.
            ///
            /// # Errors
            ///
            /// This method will either return an error if correction could not be applied, or will
            /// mutate the data with a single bit correction and return an indication of which bit
            /// was the issue.
            pub fn correct(&self, data: &mut [u8], mut crc: $uint) -> Result<Correction<$uint>, Error> {
                if (data.len() << 3) + ($uint::BITS as usize) > self.table.len() {
                    return Err(Error::DataTooLong);
                }

                // If crc(data + padding + crc) = zero of an all zero's message then the data is fine
                let crc2 = self.crc2(data, crc);
                if crc2 == self.zero_crc {
                    return Err(Error::NoError);
                }

                // Find this CRC in the table
                let mut i = 0;
                let mut error_bit = None;
                while i < self.table.len() {
                    if crc2 == self.table[i] {
                        error_bit = Some(i as $uint);
                        break;
                    }
                    i += 1;
                }

                // If the CRC isn't in the table then the data is corrupted in more than one bit, and we
                // can't correct it with this algorithm.
                let Some(error_bit) = error_bit else {
                    return Err(Error::MoreThanOneBitCorrupted);
                };

                let msg_bit_len = (data.len() << 3) as $uint;
                let offset_byte = (error_bit >> 3) as usize;
                let offset_bit = 1u8 << (error_bit & 7) as u8;
                let mut crc_error_bit = error_bit.wrapping_sub(msg_bit_len);

                // If the error bit is larger than data length then the error is in the CRC
                if error_bit >= msg_bit_len {
                    // If the CRC algorithm has reflect the CRC we need to reflect it back to
                    // correct the right bit in the input
                    if !self.crc.algorithm.refout {
                        crc_reflect!(crc_error_bit, $uint);
                    }

                    let crc_offset_bit = 1 << (crc_error_bit as u8);
                    crc ^= crc_offset_bit;
                } else {
                    // Flip erroneous bit in data
                    data[offset_byte] ^= offset_bit;
                }

                // Check if the correction worked with another CRC of data + appended CRC
                let crc2 = self.crc2(&data, crc);
                if crc2 != self.zero_crc {
                    // Correction failed, flip back the changed bit in input before returning
                    if error_bit < msg_bit_len {
                        data[offset_byte] ^= offset_bit;
                    }
                    return Err(Error::CorrectionFailed);
                }

                // If error bit is bigger than data bit length the error is in the CRC
                if error_bit >= msg_bit_len {
                    Ok(Correction::CRC { error_bit: crc_error_bit })
                } else {
                    Ok(Correction::Data { error_bit })
                }
            }

            // Calculate CRC of data + appended CRC
            fn crc2(&self, data: &[u8], mut crc: $uint) -> $uint {
                // Before calculating the CRC of (data + crc) we need to
                //  1. Modify the CRC so that it's not reflected or XOR'd
                //  2. Insert padding zeros to extend the message to length L

                // Reflect and XOR the CRC if the algorithm requires it
                if self.crc.algorithm.refout {
                    crc = crc.swap_bytes();
                }
                crc ^= self.crc.algorithm.xorout;
                let crc_bytes = crc.to_be_bytes();

                let mut digest = self.crc.digest_with_initial(0);
                digest.update(&data);
                digest.update(&crc_bytes);

                // Extend data with zeros to bit length L
                let mut remaining_bits = (self.table.len() - (data.len() << 3)) - ($uint::BITS as usize);
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
    }
}

corrector_impl!(u16);
corrector_impl!(u32);
corrector_impl!(u64);

/// Type of correction applied to the data
#[derive(Debug, PartialEq, Eq)]
pub enum Correction<W: Width> {
    /// A single bit in CRC was corrupted
    CRC {
        /// Bit offset within the CRC
        error_bit: W,
    },
    /// A single bit was the data was corrupted
    Data {
        /// Bit offset within the data
        error_bit: W,
    },
}

/// CRC Correction Error
#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    /// No corruption was found in the provided data. This is an error because the expectation when
    /// using CRC error correction is that the provided data has been corrupted.
    NoError,
    /// We currently only support error correction for one bit. This error indicates that more than
    /// one bit was corrupted in the provided data.
    MoreThanOneBitCorrupted,
    /// Provided data is too long for the `CrcCorrector`. Make sure to set `CrcCorrector::L`
    /// and `crc::Algorithm` appropriately.
    DataTooLong,
    /// Failed to correct the data. This indicates a bug in the CRC or CRC correction code. It will
    /// only be returned if a correction is applied mistakenly and the integrity double-check has
    /// caught the problem. The data passed in will have been returned to its original state.
    ///
    /// Please raise an issue on GitHub if you see this error.
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
            Self::CorrectionFailed => {
                write!(
                    f,
                    "Unable to correct data with CRC. This is bug in `crc-correction`."
                )
            }
        }
    }
}

impl core::error::Error for Error {}
