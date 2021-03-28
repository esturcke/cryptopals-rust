use crate::bytes::*;
use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockCipher, NewBlockCipher};
use aes::Aes128;

pub fn aes128(key: &[u8]) -> Aes128 {
  assert_eq!(key.len(), 16, "AES key length must be 16");
  Aes128::new(&GenericArray::from_slice(key))
}

// pub fn encrypt_block(cipher: &Aes128, block: &[u8]) -> Vec<u8> {
//   assert_eq!(block.len(), 16, "Block length must be 16 for encryption");
//   let mut copy = GenericArray::clone_from_slice(block);
//   cipher.encrypt_block(&mut copy);
//   copy.as_slice().to_vec()
// }

pub fn decrypt_block(cipher: &Aes128, block: &[u8]) -> Vec<u8> {
  assert_eq!(block.len(), 16, "Block length must be 16 for decryption");
  let mut copy = GenericArray::clone_from_slice(block);
  cipher.decrypt_block(&mut copy);
  copy.as_slice().to_vec()
}

// pub fn encrypt_cbc(key: &[u8], iv: &[u8], pt: &[u8]) -> Vec<u8> {
//   assert_eq!(key.len(), 16, "Key length must be 16 for encryption");
//   assert_eq!(iv.len(), 16, "IV length must be 16 for encryption");
//   assert_eq!(pt.len() % 16, 0, "PT length must be divisible by 16");

//   let cipher = aes128(key);
//   let mut carry = iv.to_owned();
//   let mut ct = Vec::new();
//   for block in pt.chunks(16) {
//     let ct_block = &encrypt_block(&cipher, &xor(block, &carry));
//     ct.extend_from_slice(ct_block);
//     carry = ct_block.to_owned();
//   }

//   ct
// }

pub fn decrypt_cbc(key: &[u8], iv: &[u8], ct: &[u8]) -> Vec<u8> {
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

  pt
}
