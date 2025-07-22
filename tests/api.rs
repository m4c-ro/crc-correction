use crc_correction::{CrcCorrector, Error};

use crc::{CRC_32_AIXM, Crc, Table};

const TEST_COR: CrcCorrector<288> = CrcCorrector::new(Crc::<u32, Table<1>>::new(&CRC_32_AIXM));

#[test]
fn missing_crc_fails() {
    let result = TEST_COR.correct(&mut [0, 1, 2]);

    assert_eq!(result, Err(Error::MissingAppendedCRC));
}

#[test]
fn no_error() {
    let mut msg = [0u8; 36];
    let result = TEST_COR.correct(&mut msg);

    assert_eq!(result, Err(Error::NoError));
}

#[test]
fn too_long_fails() {
    let mut msg = [0u8; 37];
    let result = TEST_COR.correct(&mut msg);

    assert_eq!(result, Err(Error::DataTooLong));
}
