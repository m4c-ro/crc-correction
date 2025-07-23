use std::sync::OnceLock;

use crc_correction::{CrcCorrector, Error};

use crc::{CRC_16_ARC, Crc, Table};

static TEST_COR: OnceLock<CrcCorrector<144, u16>> = OnceLock::new();

#[test]
fn create_at_runtime_on_heap() {
    let test_cor = Box::new(CrcCorrector::<144, u16>::new(Crc::<u16, Table<1>>::new(
        &CRC_16_ARC,
    )));

    let mut msg = [0u8; 8];
    let result = test_cor.correct(&mut msg, 0u16);
    assert_eq!(result, Err(Error::NoError));
}

#[test]
fn create_at_runtime_in_oncelock() {
    let test_cor = TEST_COR
        .get_or_init(|| CrcCorrector::<144, u16>::new(Crc::<u16, Table<1>>::new(&CRC_16_ARC)));

    let mut msg = [0u8; 8];
    let result = test_cor.correct(&mut msg, 0u16);
    assert_eq!(result, Err(Error::NoError));
}
