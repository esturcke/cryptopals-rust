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
  let initial = [
    0x67452301u32,
    0xEFCDAB89,
    0x98BADCFE,
    0x10325476,
    0xC3D2E1F0,
  ];
  sha1_extend(message, &initial, 0)
}

pub fn sha1_extend(
  message: &[u8],
  initial: &[u32; SHA1_LENGTH / 4],
  length_offset: usize,
) -> [u8; SHA1_LENGTH] {
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

  let mut digest = initial.clone();

  // Pad the message and split into chunks to process
  for m in [
    message,
    &[1u8 << 7],
    &vec![0; 63 - ((message.len() + 8) % 64)][..],
    &((message.len() + length_offset) as u64 * 8).to_be_bytes(),
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

const MD5_LENGTH: usize = 16;

pub fn md5(message: &[u8]) -> [u8; MD5_LENGTH] {
  let initial = [0x67452301u32, 0xefcdab89, 0x98badcfe, 0x10325476];
  md5_extend(message, &initial, 0)
}

pub fn md5_extend(
  message: &[u8],
  initial: &[u32; MD5_LENGTH / 4],
  length_offset: usize,
) -> [u8; MD5_LENGTH] {
  // s specifies the per-round shift amounts
  let s: [u32; 64] = [
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9,
    14, 20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10, 15,
    21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
  ];

  let k: [u32; 64] = [
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391,
  ];

  let mut digest = initial.clone();

  // Pad the message and split into chunks to process
  for message in [
    message,
    &[1u8 << 7],
    &vec![0; 63 - ((message.len() + 8) % 64)][..],
    &((message.len() + length_offset) as u64 * 8).to_le_bytes(),
  ]
  .concat()
  .chunks(16 * 4)
  {
    let mut m = [0u32; 16];
    for (i, b) in message.chunks(4).enumerate() {
      m[i] = u32::from_le_bytes([b[0], b[1], b[2], b[3]]);
    }
    let [mut a, mut b, mut c, mut d] = digest;

    for i in 0usize..64 {
      let (mut f, g) = match i {
        0..=15 => ((b & c) | (!b & d), i),
        16..=31 => ((d & b) | (!d & c), (5 * i + 1) % 16),
        32..=47 => (b ^ c ^ d, (3 * i + 5) % 16),
        48..=63 => (c ^ (b | !d), (7 * i) % 16),
        _ => panic!(),
      };

      f = f
        .overflowing_add(a)
        .0
        .overflowing_add(k[i])
        .0
        .overflowing_add(m[g])
        .0;
      a = d;
      d = c;
      c = b;
      b = b.overflowing_add(f.rotate_left(s[i])).0;
    }

    digest[0] = digest[0].overflowing_add(a).0;
    digest[1] = digest[1].overflowing_add(b).0;
    digest[2] = digest[2].overflowing_add(c).0;
    digest[3] = digest[3].overflowing_add(d).0;
  }

  let mut result = [0u8; MD5_LENGTH];
  for (i, b) in digest
    .iter()
    .flat_map(|&w| w.to_le_bytes().to_vec())
    .enumerate()
  {
    result[i] = b;
  }
  result
}

pub fn md5_mac(key: &[u8], message: &[u8]) -> [u8; MD5_LENGTH] {
  md5(&[key, message].concat())
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn md5_fox() {
    assert_eq!(
      md5(b"The quick brown fox jumps over the lazy dog.").to_hex(),
      "e4d909c290d0fb1ca068ffaddf22cbd0"
    );
  }
}
