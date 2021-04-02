use crate::bytes::*;
use crate::crypt::*;
use crate::english;
use std::fs::File;
use std::io::{BufRead, BufReader};

/// # Break fixed-nonce CTR statistically
///
/// [Set 3 / Challenge 20](https://cryptopals.com/sets/3/challenges/20)
///
/// In this file find a similar set of Base64'd plaintext. Do with them exactly what you did with the first, but solve the problem differently.
///
/// Instead of making spot guesses at to known plaintext, treat the collection of ciphertexts the same way you would repeating-key XOR.
///
/// Obviously, CTR encryption appears different from repeated-key XOR, but with a fixed nonce they are effectively the same thing.
///
/// To exploit this: take your collection of ciphertexts and truncate them to a common length (the length of the smallest ciphertext will work).
///
/// Solve the resulting concatenation of ciphertexts as if for repeating- key XOR, with a key size of the length of the ciphertext you XOR'd.
pub fn solve() -> String {
  let file = File::open("data/20.txt").expect("Failed to open file");
  let cts: Vec<_> = BufReader::new(file)
    .lines()
    .map(|line| line.unwrap().from_base64())
    .collect();

  let min_length = cts.iter().map(|ct| ct.len()).min().expect("has min size");

  let pad: Vec<_> = (0..min_length)
    .map(|i| {
      let column: Vec<_> = cts.iter().filter_map(|ct| ct.get(i)).map(|&c| c).collect();
      guess_pad_byte(&column)
    })
    .collect();

  let pts: Vec<_> = cts
    .iter()
    .map(|ct| {
      xor(&ct, &pad)
        .as_string()
        .trim()
        .chars()
        .filter(|&c| c > 7 as char)
        .collect::<String>()
    })
    .collect();

  pts.join("\n")
}

fn guess_pad_byte(ct: &[u8]) -> u8 {
  let (b, _score) = (0..=255)
    .map(|b| {
      let pt = cycled_xor(&ct, &vec![b]);
      let score = english::score(&pt);
      (b, score)
    })
    .max_by(|(_, score1), (_, score2)| score1.partial_cmp(score2).unwrap())
    .unwrap();
  b
}
