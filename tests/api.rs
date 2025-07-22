use crc_correction::{CrcCorrector, Error};

use crc::{CRC_16_ARC, CRC_32_AIXM, CRC_64_ECMA_182, Crc, Table};

const TEST_COR_16: CrcCorrector<144, u16> =
    CrcCorrector::<144, u16>::new(Crc::<u16, Table<1>>::new(&CRC_16_ARC));
const TEST_COR_32: CrcCorrector<288, u32> =
    CrcCorrector::<288, u32>::new(Crc::<u32, Table<1>>::new(&CRC_32_AIXM));
const TEST_COR_64: CrcCorrector<320, u64> =
    CrcCorrector::<320, u64>::new(Crc::<u64, Table<1>>::new(&CRC_64_ECMA_182));

#[test]
fn missing_crc_fails() {
    let result = TEST_COR_16.correct(&mut [0]);
    assert_eq!(result, Err(Error::MissingAppendedCRC));

    let result = TEST_COR_32.correct(&mut [0, 1, 2]);
    assert_eq!(result, Err(Error::MissingAppendedCRC));

    let result = TEST_COR_64.correct(&mut [0, 1, 2, 3, 4, 5, 6]);
    assert_eq!(result, Err(Error::MissingAppendedCRC));
}

#[test]
fn no_error() {
    let mut msg = [0u8; 10];
    let result = TEST_COR_16.correct(&mut msg);
    assert_eq!(result, Err(Error::NoError));

    let result = TEST_COR_32.correct(&mut msg);
    assert_eq!(result, Err(Error::NoError));

    let result = TEST_COR_64.correct(&mut msg);
    assert_eq!(result, Err(Error::NoError));
}

#[test]
fn too_long_fails() {
    let mut msg = [0u8; 19];
    let result = TEST_COR_16.correct(&mut msg);
    assert_eq!(result, Err(Error::DataTooLong));

    let mut msg = [0u8; 37];
    let result = TEST_COR_32.correct(&mut msg);
    assert_eq!(result, Err(Error::DataTooLong));

    let mut msg = [0u8; 41];
    let result = TEST_COR_64.correct(&mut msg);
    assert_eq!(result, Err(Error::DataTooLong));
}
