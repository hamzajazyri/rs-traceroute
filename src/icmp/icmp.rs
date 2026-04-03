#![allow(unused)]

pub struct IcmpHeader {
  pub kind: u8,
  pub code: u8,
  pub checksum: u16,
}

impl IcmpHeader {
  pub fn new(kind: u8, code: u8) -> Self {
    Self {
      kind,
      code,
      checksum: 0,
    }
  }
}
