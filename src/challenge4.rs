use crate::bytes::*;
use crate::english;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::str;

fn decrypt(ct: &Vec<u8>) -> (Vec<u8>, f64) {
    // Try every single byte key and look for the PT that looks most like English
    (0..=255)
        .map(|b| {
            let pt = cycled_xor(ct, &vec![b]);
            let score = english::score(&pt);
            (pt, score)
        })
        .max_by(|(_, score1), (_, score2)| score1.partial_cmp(score2).unwrap())
        .unwrap()
}

/// # Detect single-character XOR
///
/// [Set 1 / Challenge 4](https://cryptopals.com/sets/1/challenges/4)
///
/// One of the 60-character strings in this file has been encrypted by single-character XOR.
///
/// Find it.
///
/// (Your code from #3 should help.)
pub fn solve() -> String {
    let file = File::open("data/4.txt").expect("Failed to open file");
    let (pt, _score) = BufReader::new(file)
        .lines()
        .map(|line| decrypt(&line.expect("Bad line").from_hex()))
        .max_by(|(_, score1), (_, score2)| score1.partial_cmp(score2).unwrap())
        .unwrap();

    str::from_utf8(&pt).unwrap().to_string()
}
