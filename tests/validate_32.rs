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

const TEST_CORRECTORS: [CrcCorrector<288, u32>; N_ALGOS] = [
    CrcCorrector::<288, u32>::new(Crc::<u32, Table<1>>::new(&TEST_ALGOS_32[0])),
    CrcCorrector::<288, u32>::new(Crc::<u32, Table<1>>::new(&TEST_ALGOS_32[1])),
    CrcCorrector::<288, u32>::new(Crc::<u32, Table<1>>::new(&TEST_ALGOS_32[2])),
    CrcCorrector::<288, u32>::new(Crc::<u32, Table<1>>::new(&TEST_ALGOS_32[3])),
    CrcCorrector::<288, u32>::new(Crc::<u32, Table<1>>::new(&TEST_ALGOS_32[4])),
    CrcCorrector::<288, u32>::new(Crc::<u32, Table<1>>::new(&TEST_ALGOS_32[5])),
    CrcCorrector::<288, u32>::new(Crc::<u32, Table<1>>::new(&TEST_ALGOS_32[6])),
    CrcCorrector::<288, u32>::new(Crc::<u32, Table<1>>::new(&TEST_ALGOS_32[7])),
    CrcCorrector::<288, u32>::new(Crc::<u32, Table<1>>::new(&TEST_ALGOS_32[8])),
    CrcCorrector::<288, u32>::new(Crc::<u32, Table<1>>::new(&TEST_ALGOS_32[9])),
    CrcCorrector::<288, u32>::new(Crc::<u32, Table<1>>::new(&TEST_ALGOS_32[10])),
    CrcCorrector::<288, u32>::new(Crc::<u32, Table<1>>::new(&TEST_ALGOS_32[11])),
];

use proptest::prelude::*;

fn calculate_checksum_for_message(msg: &[u8], algo_index: usize) -> u32 {
    let crc = Crc::<u32, Table<1>>::new(&TEST_ALGOS_32[algo_index]);
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

        let eb = ((error_byte << 3) + error_bit) as u32;

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
    fn invalid_crcs_are_corrected(mut msg: [u8; 32], algo_index in 0..N_ALGOS, error_bit in 0..32) {
        let algo_index = algo_index as usize;
        let mut crc = calculate_checksum_for_message(&msg, algo_index);

        crc ^= 1 << (error_bit as u8);

        let result = TEST_CORRECTORS[algo_index].correct(&mut msg, crc);

        assert_eq!(result, Ok(Correction::CRC { error_bit: error_bit as u32 }));
    }

    #[test]
    fn invalid_messages_with_padding_corrected(mut msg: [u8; 10], algo_index in 0..N_ALGOS, error_byte in 0..10, error_bit in 0..8) {
        let algo_index = algo_index as usize;
        let crc = calculate_checksum_for_message(&msg, algo_index);

        msg[error_byte as usize] ^= 1 << (error_bit as u8);

        let result = TEST_CORRECTORS[algo_index].correct(&mut msg, crc);

        let eb = ((error_byte << 3) + error_bit) as u32;

        assert_eq!(result, Ok(Correction::Data { error_bit: eb }));
    }

    #[test]
    fn invalid_crcs_with_padding_are_corrected(mut msg: [u8; 10], algo_index in 0..N_ALGOS, error_bit in 0..32) {
        let algo_index = algo_index as usize;
        let mut crc = calculate_checksum_for_message(&msg, algo_index);

        crc ^= 1 << (error_bit as u8);

        let result = TEST_CORRECTORS[algo_index].correct(&mut msg, crc);

        assert_eq!(result, Ok(Correction::CRC { error_bit: error_bit as u32}));
    }

}
