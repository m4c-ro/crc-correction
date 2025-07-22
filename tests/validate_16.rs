use crc_correction::{Correction, CrcCorrector, Error};

use crc::{Algorithm, Crc, Table};

const N_ALGOS: usize = 31;
const TEST_ALGOS_16: [Algorithm<u16>; N_ALGOS] = [
    crc::CRC_16_ARC,
    crc::CRC_16_CDMA2000,
    crc::CRC_16_CMS,
    crc::CRC_16_DDS_110,
    crc::CRC_16_DECT_R,
    crc::CRC_16_DECT_X,
    crc::CRC_16_DNP,
    crc::CRC_16_EN_13757,
    crc::CRC_16_GENIBUS,
    crc::CRC_16_GSM,
    crc::CRC_16_IBM_3740,
    crc::CRC_16_IBM_SDLC,
    crc::CRC_16_ISO_IEC_14443_3_A,
    crc::CRC_16_KERMIT,
    crc::CRC_16_LJ1200,
    crc::CRC_16_M17,
    crc::CRC_16_MAXIM_DOW,
    crc::CRC_16_MCRF4XX,
    crc::CRC_16_MODBUS,
    crc::CRC_16_NRSC_5,
    crc::CRC_16_OPENSAFETY_A,
    crc::CRC_16_OPENSAFETY_B,
    crc::CRC_16_PROFIBUS,
    crc::CRC_16_RIELLO,
    crc::CRC_16_SPI_FUJITSU,
    crc::CRC_16_T10_DIF,
    crc::CRC_16_TELEDISK,
    crc::CRC_16_TMS37157,
    crc::CRC_16_UMTS,
    crc::CRC_16_USB,
    crc::CRC_16_XMODEM,
];

const TEST_CORRECTORS: [CrcCorrector<144, u16>; N_ALGOS] = [
    CrcCorrector::<144, u16>::new(Crc::<u16, Table<1>>::new(&TEST_ALGOS_16[0])),
    CrcCorrector::<144, u16>::new(Crc::<u16, Table<1>>::new(&TEST_ALGOS_16[1])),
    CrcCorrector::<144, u16>::new(Crc::<u16, Table<1>>::new(&TEST_ALGOS_16[2])),
    CrcCorrector::<144, u16>::new(Crc::<u16, Table<1>>::new(&TEST_ALGOS_16[3])),
    CrcCorrector::<144, u16>::new(Crc::<u16, Table<1>>::new(&TEST_ALGOS_16[4])),
    CrcCorrector::<144, u16>::new(Crc::<u16, Table<1>>::new(&TEST_ALGOS_16[5])),
    CrcCorrector::<144, u16>::new(Crc::<u16, Table<1>>::new(&TEST_ALGOS_16[6])),
    CrcCorrector::<144, u16>::new(Crc::<u16, Table<1>>::new(&TEST_ALGOS_16[7])),
    CrcCorrector::<144, u16>::new(Crc::<u16, Table<1>>::new(&TEST_ALGOS_16[8])),
    CrcCorrector::<144, u16>::new(Crc::<u16, Table<1>>::new(&TEST_ALGOS_16[9])),
    CrcCorrector::<144, u16>::new(Crc::<u16, Table<1>>::new(&TEST_ALGOS_16[10])),
    CrcCorrector::<144, u16>::new(Crc::<u16, Table<1>>::new(&TEST_ALGOS_16[11])),
    CrcCorrector::<144, u16>::new(Crc::<u16, Table<1>>::new(&TEST_ALGOS_16[12])),
    CrcCorrector::<144, u16>::new(Crc::<u16, Table<1>>::new(&TEST_ALGOS_16[13])),
    CrcCorrector::<144, u16>::new(Crc::<u16, Table<1>>::new(&TEST_ALGOS_16[14])),
    CrcCorrector::<144, u16>::new(Crc::<u16, Table<1>>::new(&TEST_ALGOS_16[15])),
    CrcCorrector::<144, u16>::new(Crc::<u16, Table<1>>::new(&TEST_ALGOS_16[16])),
    CrcCorrector::<144, u16>::new(Crc::<u16, Table<1>>::new(&TEST_ALGOS_16[17])),
    CrcCorrector::<144, u16>::new(Crc::<u16, Table<1>>::new(&TEST_ALGOS_16[18])),
    CrcCorrector::<144, u16>::new(Crc::<u16, Table<1>>::new(&TEST_ALGOS_16[19])),
    CrcCorrector::<144, u16>::new(Crc::<u16, Table<1>>::new(&TEST_ALGOS_16[20])),
    CrcCorrector::<144, u16>::new(Crc::<u16, Table<1>>::new(&TEST_ALGOS_16[21])),
    CrcCorrector::<144, u16>::new(Crc::<u16, Table<1>>::new(&TEST_ALGOS_16[22])),
    CrcCorrector::<144, u16>::new(Crc::<u16, Table<1>>::new(&TEST_ALGOS_16[23])),
    CrcCorrector::<144, u16>::new(Crc::<u16, Table<1>>::new(&TEST_ALGOS_16[24])),
    CrcCorrector::<144, u16>::new(Crc::<u16, Table<1>>::new(&TEST_ALGOS_16[25])),
    CrcCorrector::<144, u16>::new(Crc::<u16, Table<1>>::new(&TEST_ALGOS_16[26])),
    CrcCorrector::<144, u16>::new(Crc::<u16, Table<1>>::new(&TEST_ALGOS_16[27])),
    CrcCorrector::<144, u16>::new(Crc::<u16, Table<1>>::new(&TEST_ALGOS_16[28])),
    CrcCorrector::<144, u16>::new(Crc::<u16, Table<1>>::new(&TEST_ALGOS_16[29])),
    CrcCorrector::<144, u16>::new(Crc::<u16, Table<1>>::new(&TEST_ALGOS_16[30])),
];

use proptest::prelude::*;

fn calculate_checksum_for_message(msg: &[u8], algo_index: usize) -> u16 {
    let crc = Crc::<u16, Table<1>>::new(&TEST_ALGOS_16[algo_index]);
    crc.checksum(&msg)
}

proptest! {
    #[test]
    fn valid_messages_return_no_error(mut msg: [u8; 16], algo_index in 0..N_ALGOS) {
        let algo_index = algo_index as usize;
        let crc = calculate_checksum_for_message(&msg, algo_index);
        let result = TEST_CORRECTORS[algo_index].correct(&mut msg, crc);

        assert_eq!(result, Err(Error::NoError));
    }

    #[test]
    fn invalid_messages_are_corrected(mut msg: [u8; 16], algo_index in 0..N_ALGOS, error_byte in 0..16, error_bit in 0..8) {
        let algo_index = algo_index as usize;
        let crc = calculate_checksum_for_message(&msg, algo_index);

        msg[error_byte as usize] ^= 1 << (error_bit as u8);

        let result = TEST_CORRECTORS[algo_index].correct(&mut msg, crc);

        let eb = ((error_byte << 3) + error_bit) as u16;

        assert_eq!(result, Ok(Correction::Data { error_bit: eb }));
    }

    #[test]
    fn invalid_messages_with_more_than_one_bit_are_rejected(
        mut msg: [u8; 16],
        algo_index in 0..N_ALGOS,
        error_byte in 0..8,
        error_bit in 0..8,
        error_byte_2 in 8..16,
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
    fn invalid_crcs_are_corrected(mut msg: [u8; 16], algo_index in 0..N_ALGOS, error_bit in 0..16) {
        let algo_index = algo_index as usize;
        let mut crc = calculate_checksum_for_message(&msg, algo_index);

        crc ^= 1 << (error_bit as u8);

        let result = TEST_CORRECTORS[algo_index].correct(&mut msg, crc);

        assert_eq!(result, Ok(Correction::CRC { error_bit: error_bit as u16 }));
    }

    #[test]
    fn invalid_messages_with_padding_corrected(mut msg: [u8; 10], algo_index in 0..N_ALGOS, error_byte in 0..10, error_bit in 0..8) {
        let algo_index = algo_index as usize;
        let crc = calculate_checksum_for_message(&msg, algo_index);

        msg[error_byte as usize] ^= 1 << (error_bit as u8);

        let result = TEST_CORRECTORS[algo_index].correct(&mut msg, crc);

        let eb = ((error_byte << 3) + error_bit) as u16;

        assert_eq!(result, Ok(Correction::Data { error_bit: eb }));
    }

    #[test]
    fn invalid_crcs_with_padding_are_corrected(mut msg: [u8; 10], algo_index in 0..N_ALGOS, error_bit in 0..16) {
        let algo_index = algo_index as usize;
        let mut crc = calculate_checksum_for_message(&msg, algo_index);

        crc ^= 1 << (error_bit as u8);

        let result = TEST_CORRECTORS[algo_index].correct(&mut msg, crc);

        assert_eq!(result, Ok(Correction::CRC { error_bit: error_bit as u16 }));
    }
}
