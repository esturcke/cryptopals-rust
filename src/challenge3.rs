use crate::bytes::*;
use crate::english;

/// # Single-byte XOR cipher
///
/// [Set 1 / Challenge 3](https://cryptopals.com/sets/1/challenges/3)
///
/// The hex encoded string:
///
/// ```
/// 1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736
/// ```
///
/// ... has been XOR'd against a single character. Find the key, decrypt the message.
///
/// You can do this by hand. But don't: write code to do it for you.
///
/// How? Devise some method for "scoring" a piece of English plaintext. Character frequency is a good metric. Evaluate each output and choose the one with the best score.
/// ```
pub fn solve() -> String {
    let ct = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736".from_hex();

    // Try every single byte key and look for the PT that looks most like English
    let (pt, _score) = (0..=255)
        .map(|b| {
            let pt = cycled_xor(&ct, &vec![b]);
            let score = english::score(&pt);
            (pt, score)
        })
        .max_by(|(_, score1), (_, score2)| score1.partial_cmp(score2).unwrap())
        .unwrap();

    pt.as_string()
}
