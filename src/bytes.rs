
extern crate base64;
extern crate hex;

pub fn from_hex(encoded: &str) -> Vec<u8> {
  match hex::decode(encoded) {
    Ok(bytes) => bytes,
    _ => panic!(),
  }
}

pub fn to_hex(bytes: &Vec<u8>) -> String {
  hex::encode(bytes)
}

pub fn from_base64(encoded: &str) -> Vec<u8> {
  match base64::decode(encoded) {
    Ok(bytes) => bytes,
    _ => panic!(),
  }
}

pub fn to_base64(bytes: &Vec<u8>) -> String {
  base64::encode(&bytes)
}

pub trait Bytes {
  fn to_hex(&self) -> String;
  fn to_base64(&self) -> String;
}

pub trait EncodedBytes {
  fn from_hex(&self) -> Vec<u8>;
  fn from_base64(&self) -> Vec<u8>;
}

impl Bytes for Vec<u8> {
  fn to_hex(&self) -> String {
    to_hex(&self)
  }

  fn to_base64(&self) -> String {
    to_base64(&self)
  }
}

impl EncodedBytes for &str{
  fn from_hex(&self) -> Vec<u8> {
    from_hex(&self)
  }

  fn from_base64(&self) -> Vec<u8> {
    from_base64(&self)
  }
}