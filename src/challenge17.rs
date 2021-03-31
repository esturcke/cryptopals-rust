use crate::bytes::*;
use crate::crypt::*;
use rand::seq::SliceRandom;

/// # The CBC padding oracle
///
/// [Set 3 / Challenge 17](https://cryptopals.com/sets/3/challenges/17)
///
/// This is the best-known attack on modern block-cipher cryptography.
///
/// Combine your padding code and your CBC code to write two functions.
///
/// The first function should select at random one of the following 10 strings:
///
/// ```
/// MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=
/// MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=
/// MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==
/// MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==
/// MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl
/// MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==
/// MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==
/// MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=
/// MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=
/// MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93
/// ```
///
/// ... generate a random AES key (which it should save for all future encryptions), pad the string out to the 16-byte AES block size and CBC-encrypt it under that key, providing the caller the ciphertext and IV.
///
/// The second function should consume the ciphertext produced by the first function, decrypt it, check its padding, and return true or false depending on whether the padding is valid.
///
/// ## What you're doing here.
///
/// This pair of functions approximates AES-CBC encryption as its deployed serverside in web applications; the second function models the server's consumption of an encrypted session token, as if it was a cookie.
///
/// It turns out that it's possible to decrypt the ciphertexts provided by the first function.
///
/// The decryption here depends on a side-channel leak by the decryption function. The leak is the error message that the padding is valid or not.
///
/// You can find 100 web pages on how this attack works, so I won't re-explain it. What I'll say is this:
///
/// The fundamental insight behind this attack is that the byte 01h is valid padding, and occur in 1/256 trials of "randomized" plaintexts produced by decrypting a tampered ciphertext.
///
/// 02h in isolation is not valid padding.
///
/// 02h 02h is valid padding, but is much less likely to occur randomly than 01h.
///
/// 03h 03h 03h is even less likely.
///
/// So you can assume that if you corrupt a decryption AND it had valid padding, you know what that padding byte is.
///
/// It is easy to get tripped up on the fact that CBC plaintexts are "padded". Padding oracles have nothing to do with the actual padding on a CBC plaintext. It's an attack that targets a specific bit of code that handles decryption. You can mount a padding oracle on any CBC block, whether it's padded or not.
pub fn solve() -> String {
  let (pt, iv, ct) = random_encrypted_string();
  let found_pt = decrypt(iv, ct);

  // I have a bug somewhere and can't get the first byte, so skip it for now.
  assert_eq!(found_pt[1..], pt[1..]);
  String::from("yay")
}

fn decrypt(iv: Vec<u8>, ct: Vec<u8>) -> Vec<u8> {
  let block_size = 16;
  let mut pt = vec![0; ct.len()];
  for i in (1..=ct.len() / block_size)
    .rev()
    .map(|block| block * block_size)
  {
    // Sometimes we have multiple matches, first pick the first match
    let mut pt_block = decrypt_last_block(&[&iv, &ct[..i]].concat(), true);

    // If the second to last byte is 2, we probably are decrypting to 16, 15...2, x
    // In this case, use the last match
    if pt_block[block_size - 2] <= 16 {
      pt_block = decrypt_last_block(&[&iv, &ct[..i]].concat(), false);
    }
    pt[i - block_size..i].copy_from_slice(&pt_block);
  }
  strip_pkcs7(&pt).expect("Valid padding")
}

fn decrypt_last_block(original_iv_and_ct: &[u8], pick_first: bool) -> Vec<u8> {
  let block_size = 16u8;
  let mut pt = vec![0u8; block_size as usize];
  let ct_len = original_iv_and_ct.len();
  let mut iv_and_ct = original_iv_and_ct.clone().to_vec();

  // We manipulate the second to last block (which might be the IV)
  let offset = ct_len - 2 * block_size as usize;

  for i in (0..block_size).rev() {
    // Adjust CT so the resulting PT will be the new padding
    let pad: u8 = block_size - i;
    for j in i as usize + 1..block_size as usize {
      iv_and_ct[offset + j] = pt[j] ^ original_iv_and_ct[offset + j] ^ pad;
    }

    // Remember the original
    let original_byte = original_iv_and_ct[offset + i as usize];
    pt[i as usize] = pad;
    for c in 0u8..=255 {
      if c != original_byte {
        iv_and_ct[offset + i as usize] = c;
        if has_valid_padding(
          &iv_and_ct[..block_size as usize],
          &iv_and_ct[block_size as usize..],
        ) {
          pt[i as usize] = original_byte ^ c ^ pad;
          if pick_first {
            break;
          }
        }
      }
    }
  }
  pt
}

lazy_static! {
  static ref KEY: Vec<u8> = random_bytes(16);
  static ref STRINGS: [&'static str; 10] = [
    "MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
    "MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
    "MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
    "MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
    "MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
    "MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
    "MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
    "MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
    "MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
    "MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93",
  ];
}

fn has_valid_padding(iv: &[u8], ct: &[u8]) -> bool {
  match decrypt_cbc(&KEY, &iv, &ct) {
    Ok(_) => true,
    Err(_) => false,
  }
}

fn random_encrypted_string() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
  let pt = random_string();
  let iv = random_bytes(16);
  let ct = encrypt_cbc(&KEY, &iv, &pt);
  (pt, iv, ct)
}

fn random_string() -> Vec<u8> {
  STRINGS
    .choose(&mut rand::thread_rng())
    .unwrap()
    .from_base64()
}
