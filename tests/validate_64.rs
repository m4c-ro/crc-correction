use crc_correction::{Correction, CrcCorrector, Error};

use crc::{Algorithm, Crc, Table};

const N_ALGOS: usize = 6;
const TEST_ALGOS_64: [Algorithm<u64>; N_ALGOS] = [
    crc::CRC_64_ECMA_182,
    crc::CRC_64_GO_ISO,
    crc::CRC_64_MS,
    crc::CRC_64_REDIS,
    crc::CRC_64_WE,
    crc::CRC_64_XZ,
];

const TEST_CORRECTORS: [CrcCorrector<320, u64>; N_ALGOS] = [
    CrcCorrector::<320, u64>::new(Crc::<u64, Table<1>>::new(&TEST_ALGOS_64[0])),
    CrcCorrector::<320, u64>::new(Crc::<u64, Table<1>>::new(&TEST_ALGOS_64[1])),
    CrcCorrector::<320, u64>::new(Crc::<u64, Table<1>>::new(&TEST_ALGOS_64[2])),
    CrcCorrector::<320, u64>::new(Crc::<u64, Table<1>>::new(&TEST_ALGOS_64[3])),
    CrcCorrector::<320, u64>::new(Crc::<u64, Table<1>>::new(&TEST_ALGOS_64[4])),
    CrcCorrector::<320, u64>::new(Crc::<u64, Table<1>>::new(&TEST_ALGOS_64[5])),
];

use proptest::prelude::*;

fn add_checksum_to_message(msg: &[u8], algo_index: usize) -> Vec<u8> {
    let mut msg_vec = Vec::with_capacity(msg.len() + 8);
    msg_vec.extend_from_slice(&msg);

    let crc = Crc::<u64, Table<1>>::new(&TEST_ALGOS_64[algo_index]);
    let csum = crc.checksum(&msg);
    msg_vec.extend_from_slice(&[
        (csum >> 56) as u8,
        (csum >> 48) as u8,
        (csum >> 40) as u8,
        (csum >> 32) as u8,
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

        let eb = ((error_byte << 3) + error_bit) as u64;

        assert_eq!(result, Ok(Correction::Data { error_bit: eb }));
    }

    #[test]
    fn invalid_messages_with_more_than_one_bit_are_rejected(
        msg: [u8; 32],
        algo_index in 0..N_ALGOS,
        error_byte in 0..16,
        error_bit in 0..8,
        error_byte_2 in 16..40,
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
    fn invalid_crcs_are_corrected(msg: [u8; 32], algo_index in 0..N_ALGOS, error_byte in 0..8, error_bit in 0..8) {
        let algo_index = algo_index as usize;
        let mut msg_vec = add_checksum_to_message(&msg, algo_index);

        msg_vec[error_byte as usize + 32] ^= 1 << (error_bit as u8);

        let result = TEST_CORRECTORS[algo_index].correct(&mut msg_vec);

        let eb = ((error_byte << 3) + error_bit) as u64;

        assert_eq!(result, Ok(Correction::CRC { error_bit: eb }));
    }

    #[test]
    fn invalid_messages_with_padding_corrected(msg: [u8; 10], algo_index in 0..N_ALGOS, error_byte in 0..10, error_bit in 0..8) {
        let algo_index = algo_index as usize;
        let mut msg_vec = add_checksum_to_message(&msg, algo_index);

        msg_vec[error_byte as usize] ^= 1 << (error_bit as u8);

        let result = TEST_CORRECTORS[algo_index].correct(&mut msg_vec);

        let eb = ((error_byte << 3) + error_bit) as u64;

        assert_eq!(result, Ok(Correction::Data { error_bit: eb }));
    }

    #[test]
    fn invalid_crcs_with_padding_are_corrected(msg: [u8; 10], algo_index in 0..N_ALGOS, error_byte in 0..8, error_bit in 0..8) {
        let algo_index = algo_index as usize;
        let mut msg_vec = add_checksum_to_message(&msg, algo_index);

        msg_vec[error_byte as usize + 10] ^= 1 << (error_bit as u8);

        let result = TEST_CORRECTORS[algo_index].correct(&mut msg_vec);

        let eb = ((error_byte << 3) + error_bit) as u64;

        assert_eq!(result, Ok(Correction::CRC { error_bit: eb }));
    }

}
