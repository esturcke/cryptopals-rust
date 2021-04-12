use crate::bytes::*;
use crate::crypt::*;

use rand::prelude::*;
use rand::{thread_rng, Rng};
use std::time::SystemTime;

/// # Create the MT19937 stream cipher and break it
///
/// [Set 3 / Challenge 24](https://cryptopals.com/sets/3/challenges/24)
///
/// You can create a trivial stream cipher out of any PRNG; use it to generate a sequence of 8 bit outputs and call those outputs a keystream. XOR each byte of plaintext with each successive byte of keystream.
///
/// Write the function that does this for MT19937 using a 16-bit seed. Verify that you can encrypt and decrypt properly. This code should look similar to your CTR code.
///
/// Use your function to encrypt a known plaintext (say, 14 consecutive 'A' characters) prefixed by a random number of random characters.
///
/// From the ciphertext, recover the "key" (the 16 bit seed).
///
/// Use the same idea to generate a random "password reset token" using MT19937 seeded from the current time.
///
/// Write a function to check if any given password token is actually the product of an MT19937 PRNG seeded with the current time.
pub async fn solve() {
  let mut rng = thread_rng();
  let prefix = &random_bytes(rng.gen_range(5..=50));
  let known = &[b'A'; 14] as &[u8];
  let pt: Vec<u8> = [prefix, known].concat();
  let seed: u16 = random();
  let ct = encrypt_mt(seed as u32, &pt);

  // It's a small key space so try them all to find the seed
  let found_seed = (0u16..)
    .find(|&seed| {
      let pt = decrypt_mt(seed as u32, &ct);
      pt.windows(14).any(|window| window == known)
    })
    .unwrap();

  assert_eq!(seed, found_seed);

  // Now generate the password reset token
  let prefix = &random_bytes(rng.gen_range(5..=50));
  let known = &[b'A'; 14] as &[u8];
  let pt: Vec<u8> = [prefix, known].concat();
  let ct = encrypt_mt(now(), &pt);

  // Some time later
  let later = now() + rng.gen_range(100u32..=1000);
  let is_mt = (later - 4000..later).rev().any(|seed| {
    let pt = decrypt_mt(seed, &ct);
    pt.windows(14).any(|window| window == known)
  });

  assert!(is_mt);
}

fn now() -> u32 {
  SystemTime::now()
    .duration_since(SystemTime::UNIX_EPOCH)
    .unwrap()
    .as_secs() as u32
}
