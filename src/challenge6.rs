use crate::bytes::*;
use crate::crack;
use std::fs;

/// # Break repeating-key XOR
///
/// [Set 1 / Challenge 6](https://cryptopals.com/sets/1/challenges/6)
///
/// [There's a file here](https://cryptopals.com/static/challenge-data/6.txt). It's been base64'd after being encrypted with repeating-key XOR.
///
/// Decrypt it.
///
/// Here's how:
///
/// 1. Let KEYSIZE be the guessed length of the key; try values from 2 to (say) 40.
/// 2. Write a function to compute the edit distance/Hamming distance between two strings. The Hamming distance is just the number of differing bits. The distance between:
///
///     ```
///     this is a test
///     ```
///
///     and
///
///     ```
///     wokka wokka!!!
///     ```
///
///     is 37. Make sure your code agrees before you proceed.
///
/// 3. For each KEYSIZE, take the first KEYSIZE worth of bytes, and the second KEYSIZE worth of bytes, and find the edit distance between them. Normalize this result by dividing by KEYSIZE.
/// 4. The KEYSIZE with the smallest normalized edit distance is probably the key. You could proceed perhaps with the smallest 2-3 KEYSIZE values. Or take 4 KEYSIZE blocks instead of 2 and average the distances.
/// 5. Now that you probably know the KEYSIZE: break the ciphertext into blocks of KEYSIZE length.
/// 6. Now transpose the blocks: make a block that is the first byte of every block, and a block that is the second byte of every block, and so on.
/// 7, Solve each block as if it was single-character XOR. You already have code to do this.
/// 8. For each block, the single-byte XOR key that produces the best looking histogram is the repeating-key XOR key byte for that block. Put them together and you have the key.
///
/// This code is going to turn out to be surprisingly useful later on. Breaking repeating-key XOR ("Vigenere") statistically is obviously an academic exercise, a "Crypto 101" thing. But more people "know how" to break it than can actually break it, and a similar technique breaks something much more important.
pub async fn solve(solution: &str) {
  let ct = fs::read_to_string("data/6.txt")
    .expect("Can't load ct")
    .replace("\n", "")
    .from_base64();
  let key_length = guess_key_length(&ct);

  // construct the key
  let mut key: Vec<u8> = Vec::new();
  for chunk in cycled_chunk(&ct, key_length) {
    key.push(crack::guess_xor_key(&chunk));
  }

  assert_eq!(cycled_xor(&ct, &key).as_string(), solution);
}

fn guess_key_length(ct: &[u8]) -> usize {
  (1..40usize)
    .map(|l| (l, sampled_edit_distance(ct, l)))
    .min_by(|(_, dist1), (_, dist2)| dist1.partial_cmp(dist2).unwrap())
    .unwrap()
    .0
}

fn sampled_edit_distance(ct: &[u8], l: usize) -> f64 {
  let samples = 40usize;
  let sum: u32 = (0..samples)
    .map(|offset| edit_distance(&ct[offset..offset + l], &ct[offset + l..offset + 2 * l]))
    .sum();
  sum as f64 / (samples * l) as f64
}
