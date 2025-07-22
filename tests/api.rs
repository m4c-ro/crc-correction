use crc_correction::{Correction, CrcCorrector, Error};

use crc::{CRC_16_ARC, CRC_32_AIXM, CRC_64_ECMA_182, Crc, Table};

const TEST_COR_16: CrcCorrector<144, u16> =
    CrcCorrector::<144, u16>::new(Crc::<u16, Table<1>>::new(&CRC_16_ARC));
const TEST_COR_32: CrcCorrector<288, u32> =
    CrcCorrector::<288, u32>::new(Crc::<u32, Table<1>>::new(&CRC_32_AIXM));
const TEST_COR_64: CrcCorrector<320, u64> =
    CrcCorrector::<320, u64>::new(Crc::<u64, Table<1>>::new(&CRC_64_ECMA_182));

#[test]
fn no_error() {
    let mut msg = [0u8; 8];
    let result = TEST_COR_16.correct(&mut msg, 0u16);
    assert_eq!(result, Err(Error::NoError));

    let result = TEST_COR_32.correct(&mut msg, 0u32);
    assert_eq!(result, Err(Error::NoError));

    let result = TEST_COR_64.correct(&mut msg, 0u64);
    assert_eq!(result, Err(Error::NoError));
}

#[test]
fn too_long_fails() {
    let mut msg = [0u8; 17];
    let result = TEST_COR_16.correct(&mut msg, 0u16);
    assert_eq!(result, Err(Error::DataTooLong));

    let mut msg = [0u8; 33];
    let result = TEST_COR_32.correct(&mut msg, 0u32);
    assert_eq!(result, Err(Error::DataTooLong));

    let mut msg = [0u8; 33];
    let result = TEST_COR_64.correct(&mut msg, 0u64);
    assert_eq!(result, Err(Error::DataTooLong));
}

fn test_send_sync<T: Sync + Sync>(_: T) {}

#[test]
fn corrector_is_send_sync() {
    test_send_sync(TEST_COR_16);
}

#[test]
fn correction_is_send_sync() {
    let mut msg = [0u8; 8];
    let crc = Crc::<u16, Table<1>>::new(&CRC_16_ARC);
    let crc = crc.checksum(&msg);

    msg[1] ^= 1 << 1;

    let result = TEST_COR_16.correct(&mut msg, crc);
    assert_eq!(result, Ok(Correction::Data { error_bit: 9 }));

    let c = result.unwrap();
    test_send_sync(c);
}

#[test]
fn error_is_send_sync() {
    let mut msg = [0u8; 8];
    let result = TEST_COR_16.correct(&mut msg, 0u16);
    assert_eq!(result, Err(Error::NoError));

    let e = result.unwrap_err();
    test_send_sync(e);
}
