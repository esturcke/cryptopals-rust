use std::cmp;
use std::str;
extern crate base64;
extern crate hex;

use rand::prelude::*;

pub fn random_bytes(n: usize) -> Vec<u8> {
  (0..n).map(|_| random()).collect()
}

pub fn random_8() -> [u8; 8] {
  let mut value = [0u8; 8];
  for (i, &b) in random_bytes(8).iter().enumerate() {
    value[i] = b;
  }
  value
}

pub fn random_16() -> [u8; 16] {
  let mut value = [0u8; 16];
  for (i, &b) in random_bytes(16).iter().enumerate() {
    value[i] = b;
  }
  value
}

pub fn from_hex(encoded: &str) -> Vec<u8> {
  hex::decode(encoded).expect("Failed to decode hex string")
}

pub fn to_hex(bytes: &[u8]) -> String {
  hex::encode(bytes)
}

pub fn from_base64(encoded: &str) -> Vec<u8> {
  base64::decode(encoded).expect("Failed to decode Base64 string")
}

pub fn to_base64(bytes: &[u8]) -> String {
  base64::encode(&bytes)
}

pub fn xor(a: &[u8], b: &[u8]) -> Vec<u8> {
  let len = cmp::min(a.len(), b.len());
  let mut c = Vec::new();
  for i in 0..len {
    c.push(a[i] ^ b[i])
  }
  c
}

pub fn not(a: &[u8]) -> Vec<u8> {
  a.iter().map(|&b| !b).collect()
}

pub fn cycled_xor(a: &[u8], b: &[u8]) -> Vec<u8> {
  let mut c = Vec::new();
  for i in 0..a.len() {
    c.push(a[i] ^ b[i % b.len()])
  }
  c
}

pub fn edit_distance(a: &[u8], b: &[u8]) -> u32 {
  let mut distance = 0;
  let len = cmp::min(a.len(), b.len());
  for i in 0..len {
    distance += (a[i] ^ b[i]).count_ones()
  }
  distance
}

pub fn cycled_chunk(a: &[u8], len: usize) -> Vec<Vec<u8>> {
  let mut chunks: Vec<Vec<u8>> = vec![Vec::new(); len];
  for chunk in a.chunks(len) {
    for (i, &b) in chunk.iter().enumerate() {
      chunks[i].push(b)
    }
  }
  chunks
}

pub fn pad_pkcs7(a: &[u8], block_size: usize) -> Vec<u8> {
  let n = block_size - a.len() % block_size;
  [a, &vec![n as u8; n][..]].concat()
}

pub fn strip_pkcs7(a: &[u8]) -> Result<Vec<u8>, &'static str> {
  let n = a[a.len() - 1];
  if n as usize >= a.len() {
    return Err("Invalid padding");
  }
  let (message, padding) = a.split_at(a.len() - n as usize);
  if &vec![n; n as usize][..] == padding {
    Ok(message.to_owned())
  } else {
    Err("Invalid padding")
  }
}

pub trait Bytes {
  fn to_hex(&self) -> String;
  fn to_base64(&self) -> String;
  fn as_string(&self) -> String;
  fn pad_pkcs7(&self, block_size: usize) -> Vec<u8>;
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

  fn as_string(&self) -> String {
    str::from_utf8(&self).unwrap().to_string()
  }

  fn pad_pkcs7(&self, block_size: usize) -> Vec<u8> {
    pad_pkcs7(&self, block_size)
  }
}

impl Bytes for [u8] {
  fn to_hex(&self) -> String {
    to_hex(&self)
  }

  fn to_base64(&self) -> String {
    to_base64(&self)
  }

  fn as_string(&self) -> String {
    str::from_utf8(&self).unwrap().to_string()
  }

  fn pad_pkcs7(&self, block_size: usize) -> Vec<u8> {
    pad_pkcs7(&self, block_size)
  }
}

impl EncodedBytes for &str {
  fn from_hex(&self) -> Vec<u8> {
    from_hex(&self)
  }

  fn from_base64(&self) -> Vec<u8> {
    from_base64(&self)
  }
}

impl EncodedBytes for String {
  fn from_hex(&self) -> Vec<u8> {
    from_hex(&self)
  }

  fn from_base64(&self) -> Vec<u8> {
    from_base64(&self)
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn wokka_wokka_edit_distance() {
    assert_eq!(edit_distance(b"this is a test", b"wokka wokka!!!"), 37);
  }
}
