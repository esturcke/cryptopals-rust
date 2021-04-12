use crate::crypt::*;
use rand::seq::SliceRandom;
use std::fs::File;
use std::io::{BufRead, BufReader};

/// # Break an MD4 keyed MAC using length extension
///
/// [Set 4 / Challenge 30](https://cryptopals.com/sets/4/challenges/30)
///
/// Second verse, same as the first, but use MD4 instead of SHA-1. Having done this attack once against SHA-1, the MD4 variant should take much less time; mostly just the time you'll spend Googling for an implementation of MD4.
///
/// ##You're thinking, why did we bother with this?
///
/// Blame Stripe. In their second CTF game, the second-to-last challenge involved breaking an H(k, m) MAC with SHA1. Which meant that SHA1 code was floating all over the Internet. MD4 code, not so much.
pub async fn solve() {
  let (message, mac) = get_message_and_mac();
  let suffix = b";admin=true";
  let (forged_message, forged_mac) = (1..)
    .map(|key_length| {
      let length = key_length + message.len();
      let forged_message: Vec<_> = [
        message,
        &[1u8 << 7],
        &vec![0; 63 - ((length + 8) % 64)][..],
        &(length as u64 * 8).to_le_bytes(),
        suffix,
      ]
      .concat();
      let mut initial = [0u32; 4];
      for (i, word) in mac.chunks(4).enumerate() {
        initial[i] = u32::from_le_bytes([word[0], word[1], word[2], word[3]]);
      }
      let forged_mac = md5_extend(
        suffix,
        &initial,
        forged_message.len() - suffix.len() + key_length,
      );
      (forged_message, forged_mac)
    })
    .find(|(message, mac)| check_mac(message, mac))
    .expect("to be able to forge");

  assert!(check_mac(&forged_message, &forged_mac));
}

const MESSAGE: &'static [u8] =
  b"comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon";

fn get_message_and_mac() -> (&'static [u8], [u8; 16]) {
  let mac = md5_mac(&KEY, &MESSAGE);
  (MESSAGE, mac)
}

fn check_mac(message: &[u8], mac: &[u8]) -> bool {
  md5_mac(&KEY, message) == mac
}

lazy_static! {
  static ref KEY: Vec<u8> = {
    let file = File::open("/usr/share/dict/words").expect("Failed to open dict");
    let lines: Vec<_> = BufReader::new(file)
      .lines()
      .map(|l| l.expect("Can read word"))
      .collect();
    lines
      .choose(&mut rand::thread_rng())
      .expect("")
      .as_bytes()
      .to_vec()
  };
}
