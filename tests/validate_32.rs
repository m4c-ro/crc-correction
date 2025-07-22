use crc_correction::{Correction, CrcCorrector, Error};

use crc::{Algorithm, Crc, Table};

const N_ALGOS: usize = 12;
const TEST_ALGOS_32: [Algorithm<u32>; N_ALGOS] = [
    crc::CRC_32_AIXM,
    crc::CRC_32_AUTOSAR,
    crc::CRC_32_BASE91_D,
    crc::CRC_32_BZIP2,
    crc::CRC_32_CD_ROM_EDC,
    crc::CRC_32_CKSUM,
    crc::CRC_32_ISCSI,
    crc::CRC_32_ISO_HDLC,
    crc::CRC_32_JAMCRC,
    crc::CRC_32_MEF,
    crc::CRC_32_MPEG_2,
    crc::CRC_32_XFER,
];

const TEST_CORRECTORS: [CrcCorrector<288>; N_ALGOS] = [
    CrcCorrector::new(Crc::<u32, Table<1>>::new(&TEST_ALGOS_32[0])),
    CrcCorrector::new(Crc::<u32, Table<1>>::new(&TEST_ALGOS_32[1])),
    CrcCorrector::new(Crc::<u32, Table<1>>::new(&TEST_ALGOS_32[2])),
    CrcCorrector::new(Crc::<u32, Table<1>>::new(&TEST_ALGOS_32[3])),
    CrcCorrector::new(Crc::<u32, Table<1>>::new(&TEST_ALGOS_32[4])),
    CrcCorrector::new(Crc::<u32, Table<1>>::new(&TEST_ALGOS_32[5])),
    CrcCorrector::new(Crc::<u32, Table<1>>::new(&TEST_ALGOS_32[6])),
    CrcCorrector::new(Crc::<u32, Table<1>>::new(&TEST_ALGOS_32[7])),
    CrcCorrector::new(Crc::<u32, Table<1>>::new(&TEST_ALGOS_32[8])),
    CrcCorrector::new(Crc::<u32, Table<1>>::new(&TEST_ALGOS_32[9])),
    CrcCorrector::new(Crc::<u32, Table<1>>::new(&TEST_ALGOS_32[10])),
    CrcCorrector::new(Crc::<u32, Table<1>>::new(&TEST_ALGOS_32[11])),
];

use proptest::prelude::*;

fn add_checksum_to_message(msg: &[u8], algo_index: usize) -> Vec<u8> {
    let mut msg_vec = Vec::with_capacity(msg.len() + 4);
    msg_vec.extend_from_slice(&msg);

    let crc = Crc::<u32, Table<1>>::new(&TEST_ALGOS_32[algo_index]);
    let csum = crc.checksum(&msg);
    msg_vec.extend_from_slice(&[
        (csum >> 24) as u8,
        (csum >> 16) as u8,
        (csum >> 8) as u8,
        csum as u8,
    ]);

    msg_vec
}

proptest! {
    #[test]
    fn valid_messages_return_no_error(msg: [u8; 32], algo_index in 0..N_ALGOS) {
        let algo_index = algo_index as usize;
        let mut msg_vec = add_checksum_to_message(&msg, algo_index);
        let result = TEST_CORRECTORS[algo_index].correct(&mut msg_vec);

        assert_eq!(result, Err(Error::NoError));
    }

    #[test]
    fn invalid_messages_are_corrected(msg: [u8; 32], algo_index in 0..N_ALGOS, error_byte in 0..32, error_bit in 0..8) {
        let algo_index = algo_index as usize;
        let mut msg_vec = add_checksum_to_message(&msg, algo_index);

        msg_vec[error_byte as usize] ^= 1 << (error_bit as u8);

        let result = TEST_CORRECTORS[algo_index].correct(&mut msg_vec);

        let eb = ((error_byte << 3) + error_bit) as u32;

        assert_eq!(result, Ok(Correction::Data { error_bit: eb }));
    }

    #[test]
    fn invalid_messages_with_more_than_one_bit_are_rejected(
        msg: [u8; 32],
        algo_index in 0..N_ALGOS,
        error_byte in 0..16,
        error_bit in 0..8,
        error_byte_2 in 16..36,
        error_bit_2 in 0..8,
    ) {
        let algo_index = algo_index as usize;
        let mut msg_vec = add_checksum_to_message(&msg, algo_index);

        msg_vec[error_byte as usize] ^= 1 << (error_bit as u8);
        msg_vec[error_byte_2 as usize] ^= 1 << (error_bit_2 as u8);

        let result = TEST_CORRECTORS[algo_index].correct(&mut msg_vec);

        assert_eq!(result, Err(Error::MoreThanOneBitCorrupted));
    }

    #[test]
    fn invalid_crcs_are_corrected(msg: [u8; 32], algo_index in 0..N_ALGOS, error_byte in 0..4, error_bit in 0..8) {
        let algo_index = algo_index as usize;
        let mut msg_vec = add_checksum_to_message(&msg, algo_index);

        msg_vec[error_byte as usize + 32] ^= 1 << (error_bit as u8);

        let result = TEST_CORRECTORS[algo_index].correct(&mut msg_vec);

        let eb = ((error_byte << 3) + error_bit) as u32;

        assert_eq!(result, Ok(Correction::CRC { error_bit: eb }));
    }

    #[test]
    fn invalid_messages_with_padding_corrected(msg: [u8; 10], algo_index in 0..N_ALGOS, error_byte in 0..10, error_bit in 0..8) {
        let algo_index = algo_index as usize;
        let mut msg_vec = add_checksum_to_message(&msg, algo_index);

        msg_vec[error_byte as usize] ^= 1 << (error_bit as u8);

        let result = TEST_CORRECTORS[algo_index].correct(&mut msg_vec);

        let eb = ((error_byte << 3) + error_bit) as u32;

        assert_eq!(result, Ok(Correction::Data { error_bit: eb }));
    }

    #[test]
    fn invalid_crcs_with_padding_are_corrected(msg: [u8; 10], algo_index in 0..N_ALGOS, error_byte in 0..4, error_bit in 0..8) {
        let algo_index = algo_index as usize;
        let mut msg_vec = add_checksum_to_message(&msg, algo_index);

        msg_vec[error_byte as usize + 10] ^= 1 << (error_bit as u8);

        let result = TEST_CORRECTORS[algo_index].correct(&mut msg_vec);

        let eb = ((error_byte << 3) + error_bit) as u32;

        assert_eq!(result, Ok(Correction::CRC { error_bit: eb }));
    }

}
