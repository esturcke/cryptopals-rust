use crate::bytes::*;
use crate::english;

pub fn guess_xor_key(ct: &[u8]) -> u8 {
    // Try every single byte key and look for the PT that looks most like English
    (0..=255)
        .map(|b| {
            let pt = cycled_xor(ct, &vec![b]);
            let score = english::score(&pt);
            (b, score)
        })
        .max_by(|(_, score1), (_, score2)| score1.partial_cmp(score2).unwrap())
        .unwrap()
        .0
}
