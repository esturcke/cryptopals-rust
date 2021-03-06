use crate::bytes::*;

/// # Fixed XOR
///
/// [Set 1 / Challenge 2](https://cryptopals.com/sets/1/challenges/2)
///
/// Write a function that takes two equal-length buffers and produces their XOR combination.
/// If your function works properly, then when you feed it the string:
///
/// ```
/// 1c0111001f010100061a024b53535009181c
/// ```
///
/// ... after hex decoding, and when XOR'd against:
///
/// ```
/// 686974207468652062756c6c277320657965
/// ```
///
/// ... should produce:
///
/// ```
/// 746865206b696420646f6e277420706c6179
/// ```
pub async fn solve() {
  assert_eq!(
    xor(
      &"1c0111001f010100061a024b53535009181c".from_hex(),
      &"686974207468652062756c6c277320657965".from_hex(),
    )
    .to_hex(),
    "746865206b696420646f6e277420706c6179",
  );
}
