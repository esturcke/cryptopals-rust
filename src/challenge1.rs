use crate::bytes::*;

/// # Convert hex to base64
///
/// [Set 1 / Challenge 1](https://cryptopals.com/sets/1/challenges/1)
///
/// The string:
///
/// ```
/// 49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d
/// ```
///
/// Should produce:
///
/// ```
/// SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t
/// ```
///
/// So go ahead and make that happen. You'll need to use this code for the rest of the exercises.
pub async fn solve() {
  assert_eq!("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
    .from_hex()
    .to_base64(), "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t");
}
