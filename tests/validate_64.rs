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

fn calculate_checksum_for_message(msg: &[u8], algo_index: usize) -> u64 {
    let crc = Crc::<u64, Table<1>>::new(&TEST_ALGOS_64[algo_index]);
    crc.checksum(&msg)
}

proptest! {
    #[test]
    fn valid_messages_return_no_error(mut msg: [u8; 32], algo_index in 0..N_ALGOS) {
        let algo_index = algo_index as usize;
        let crc = calculate_checksum_for_message(&msg, algo_index);
        let result = TEST_CORRECTORS[algo_index].correct(&mut msg, crc);

        assert_eq!(result, Err(Error::NoError));
    }

    #[test]
    fn invalid_messages_are_corrected(mut msg: [u8; 32], algo_index in 0..N_ALGOS, error_byte in 0..32, error_bit in 0..8) {
        let algo_index = algo_index as usize;
        let crc = calculate_checksum_for_message(&msg, algo_index);

        msg[error_byte as usize] ^= 1 << (error_bit as u8);

        let result = TEST_CORRECTORS[algo_index].correct(&mut msg, crc);

        let eb = ((error_byte << 3) + error_bit) as u64;

        assert_eq!(result, Ok(Correction::Data { error_bit: eb }));
    }

    #[test]
    fn invalid_messages_with_more_than_one_bit_are_rejected(
        mut msg: [u8; 32],
        algo_index in 0..N_ALGOS,
        error_byte in 0..16,
        error_bit in 0..8,
        error_byte_2 in 16..32,
        error_bit_2 in 0..8,
    ) {
        let algo_index = algo_index as usize;
        let crc = calculate_checksum_for_message(&msg, algo_index);

        msg[error_byte as usize] ^= 1 << (error_bit as u8);
        msg[error_byte_2 as usize] ^= 1 << (error_bit_2 as u8);

        let result = TEST_CORRECTORS[algo_index].correct(&mut msg, crc);

        assert_eq!(result, Err(Error::MoreThanOneBitCorrupted));
    }

    #[test]
    fn invalid_crcs_are_corrected(mut msg: [u8; 32], algo_index in 0..N_ALGOS, error_bit in 0..64) {
        let algo_index = algo_index as usize;
        let mut crc = calculate_checksum_for_message(&msg, algo_index);

        crc ^= 1 << (error_bit as u8);

        let result = TEST_CORRECTORS[algo_index].correct(&mut msg, crc);

        assert_eq!(result, Ok(Correction::CRC { error_bit: error_bit as u64 }));
    }

    #[test]
    fn invalid_messages_with_padding_corrected(mut msg: [u8; 10], algo_index in 0..N_ALGOS, error_byte in 0..10, error_bit in 0..8) {
        let algo_index = algo_index as usize;
        let crc = calculate_checksum_for_message(&msg, algo_index);

        msg[error_byte as usize] ^= 1 << (error_bit as u8);

        let result = TEST_CORRECTORS[algo_index].correct(&mut msg, crc);

        let eb = ((error_byte << 3) + error_bit) as u64;

        assert_eq!(result, Ok(Correction::Data { error_bit: eb }));
    }

    #[test]
    fn invalid_crcs_with_padding_are_corrected(mut msg: [u8; 10], algo_index in 0..N_ALGOS, error_bit in 0..64) {
        let algo_index = algo_index as usize;
        let mut crc = calculate_checksum_for_message(&msg, algo_index);

        crc ^= 1 << (error_bit as u8);

        let result = TEST_CORRECTORS[algo_index].correct(&mut msg, crc);

        assert_eq!(result, Ok(Correction::CRC { error_bit: error_bit as u64 }));
    }

}
