# CRC Correction

Attempt to correct corrupted data with a CRC. This library is able to correct single bit errors in
data so long as the CRC algorithm is known and the data is less than a pre-defined length. Single
bit errors in the CRC are also fixable.

Uses the [crc](https://crates.io/crates/crc) crate for the actual CRC implementations. We support
all 16, 32 and 64 bit CRC algorithms from [crc](https://crates.io/crates/crc).

### Example

```rust
use crc::{Crc, Table, CRC_32_CKSUM};
use crc_correction::{CrcCorrector, Error};

// Maximum message length, in bits, including CRC bits.
const MAX_MSG_LEN: usize = 256;

// CRC instance to use
const CRC: Crc<u32, Table<1>> =
    Crc::<u32, Table<1>>::new(&CRC_32_CKSUM);

// Corrector instance. Note that this generates a lookup
// table for correction at compile time, so runtime
// checks are faster.
const CORRECTOR: CrcCorrector::<MAX_MSG_LEN, u32> =
    CrcCorrector::<MAX_MSG_LEN, u32>::new(CRC);

fn main() {
    // Note that the length leaves 4 bytes room for CRC compared to MAX_MSG_LEN
    let mut msg = [123u8; 28];
    let crc = 0u32;

    let result = CORRECTOR.correct(&mut msg, crc);

    // Since we didn't calculate a CRC in this example
    assert_eq!(result, Err(Error::MoreThanOneBitCorrupted));
}

### Compile Times

A lookup table is generated containing a CRC for every bit in the desired maximum message length.
This can take some time to generate. It is recommended to use another form of error correction for
very long messages. If the compiler complains about very long constant evaluation you may generate
the table at runtime by initializing `CrcCorrector` on the heap, or disable the compiler lint as
follows:

```rust
use crc::{Crc, Table, CRC_32_CKSUM};
use crc_correction::CrcCorrector;

const MAX_MSG_LEN: usize = 256;
const CRC: Crc<u32, Table<1>> =
    Crc::<u32, Table<1>>::new(&CRC_32_CKSUM);

// Allow the corrector table generation to take a long
// time during compilation
#[allow(long_running_const_eval)]
const CORRECTOR: CrcCorrector::<MAX_MSG_LEN, u32> =
    CrcCorrector::<MAX_MSG_LEN, u32>::new(CRC);
```
