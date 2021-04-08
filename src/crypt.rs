use crate::bytes::*;
use crate::rand::*;
use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockCipher, NewBlockCipher};
use aes::Aes128;

pub fn aes128(key: &[u8]) -> Aes128 {
  assert_eq!(key.len(), 16, "AES key length must be 16");
  Aes128::new(&GenericArray::from_slice(key))
}

pub fn encrypt_block(cipher: &Aes128, block: &[u8]) -> Vec<u8> {
  assert_eq!(block.len(), 16, "Block length must be 16 for encryption");
  let mut copy = GenericArray::clone_from_slice(block);
  cipher.encrypt_block(&mut copy);
  copy.as_slice().to_vec()
}

pub fn decrypt_block(cipher: &Aes128, block: &[u8]) -> Vec<u8> {
  assert_eq!(block.len(), 16, "Block length must be 16 for decryption");
  let mut copy = GenericArray::clone_from_slice(block);
  cipher.decrypt_block(&mut copy);
  copy.as_slice().to_vec()
}

pub fn encrypt_ecb(key: &[u8], pt: &[u8]) -> Vec<u8> {
  assert_eq!(key.len(), 16, "Key length must be 16 for encryption");

  let cipher = aes128(key);
  let ct: Vec<u8> = pad_pkcs7(pt, 16)
    .chunks(16)
    .flat_map(|block| encrypt_block(&cipher, block))
    .collect();

  ct
}

pub fn decrypt_ecb(key: &[u8], ct: &[u8]) -> Result<Vec<u8>, &'static str> {
  assert_eq!(key.len(), 16, "Key length must be 16 for decryption");
  assert_eq!(ct.len() % 16, 0, "CT length must be divisible by 16");

  let cipher = aes128(key);
  let pt: Vec<u8> = ct
    .chunks(16)
    .flat_map(|block| decrypt_block(&cipher, block))
    .collect();
  strip_pkcs7(&pt)
}

pub fn encrypt_cbc(key: &[u8], iv: &[u8], pt: &[u8]) -> Vec<u8> {
  assert_eq!(key.len(), 16, "Key length must be 16 for encryption");
  assert_eq!(iv.len(), 16, "IV length must be 16 for encryption");

  let cipher = aes128(key);
  let mut carry = iv.to_owned();
  let mut ct = Vec::new();
  for block in pad_pkcs7(pt, 16).chunks(16) {
    let ct_block = &encrypt_block(&cipher, &xor(block, &carry));
    ct.extend_from_slice(ct_block);
    carry = ct_block.to_owned();
  }

  ct
}

pub fn decrypt_cbc(key: &[u8], iv: &[u8], ct: &[u8]) -> Result<Vec<u8>, &'static str> {
  assert_eq!(key.len(), 16, "Key length must be 16 for decryption");
  assert_eq!(iv.len(), 16, "IV length must be 16 for decryption");
  assert_eq!(ct.len() % 16, 0, "CT length must be divisible by 16");

  let cipher = aes128(key);
  let mut carry = iv.to_owned();
  let mut pt = Vec::new();
  for block in ct.chunks(16) {
    pt.extend_from_slice(&xor(&carry, &decrypt_block(&cipher, block)));
    carry = block.to_owned();
  }

  strip_pkcs7(&pt)
}

pub fn encrypt_ctr(key: &[u8], nonce: &[u8; 8], pt: &[u8]) -> Vec<u8> {
  assert_eq!(key.len(), 16, "Key length must be 16 for decryption");
  assert_eq!(nonce.len(), 8, "Nonce length must be 8 for decryption");
  let cipher = aes128(key);
  let mut ct = Vec::new();
  for (count, block) in pt.chunks(16).enumerate() {
    let pad = &encrypt_block(&cipher, &[*nonce, count.to_le_bytes()].concat());
    ct.extend_from_slice(&xor(&pad, block));
  }

  ct
}

pub fn decrypt_ctr(key: &[u8], nonce: &[u8; 8], ct: &[u8]) -> Vec<u8> {
  encrypt_ctr(key, nonce, ct)
}

pub fn encrypt_mt(seed: u32, pt: &[u8]) -> Vec<u8> {
  let generator = random_from_seed(seed);
  let mut ct = Vec::new();
  for (block, pad) in pt.chunks(4).zip(generator) {
    ct.extend_from_slice(&xor(&pad.to_le_bytes(), block));
  }

  ct
}

pub fn decrypt_mt(seed: u32, ct: &[u8]) -> Vec<u8> {
  encrypt_mt(seed, ct)
}

const SHA1_LENGTH: usize = 20;

pub fn sha1(message: &[u8]) -> [u8; SHA1_LENGTH] {
  let f = |t: usize, b: u32, c: u32, d: u32| match t {
    0..=19 => (b & c) | (!b & d),
    20..=39 => b ^ c ^ d,
    40..=59 => (b & c) | (b & d) | (c & d),
    60..=79 => b ^ c ^ d,
    _ => panic!("Invalid value {} for t", t),
  };

  let k = |t: usize| match t {
    0..=19 => 0x5A827999u32,
    20..=39 => 0x6ED9EBA1,
    40..=59 => 0x8F1BBCDC,
    60..=79 => 0xCA62C1D6,
    _ => panic!("Invalid value {} for t", t),
  };

  let mut digest = [
    0x67452301u32,
    0xEFCDAB89,
    0x98BADCFE,
    0x10325476,
    0xC3D2E1F0,
  ];

  // Pad the message and split into chunks to process
  for m in [
    message,
    &[1u8 << 7],
    &vec![0; 63 - ((message.len() + 8) % 64)][..],
    &(message.len() as u64 * 8).to_be_bytes(),
  ]
  .concat()
  .chunks(16 * 4)
  {
    let mut w = [0u32; 80];

    // 1.a
    for i in 0..16 {
      w[i] = u32::from_be_bytes([m[i * 4], m[i * 4 + 1], m[i * 4 + 2], m[i * 4 + 3]]);
    }

    // 1.b
    for t in 16..80 {
      w[t] = (w[t - 3] ^ w[t - 8] ^ w[t - 14] ^ w[t - 16]).rotate_left(1);
    }

    // 1.c
    let [mut a, mut b, mut c, mut d, mut e] = digest;

    // 1.d
    for t in 0..80 {
      let temp = a.rotate_left(5) + f(t, b, c, d) + e + w[t] + k(t);
      e = d;
      d = c;
      c = b.rotate_left(30);
      b = a;
      a = temp;
    }

    //  1.e.
    digest[0] += a;
    digest[1] += b;
    digest[2] += c;
    digest[3] += d;
    digest[4] += e;
  }

  let mut result = [0u8; SHA1_LENGTH];
  for (i, b) in digest
    .iter()
    .flat_map(|&w| w.to_be_bytes().to_vec())
    .enumerate()
  {
    result[i] = b;
  }
  result
}

pub fn sha1_mac(key: &[u8], message: &[u8]) -> [u8; SHA1_LENGTH] {
  sha1(&[key, message].concat())
}
