use crate::rand::*;

/// # Implement the MT19937 Mersenne Twister RNG
///
/// [Set 3 / Challenge 21](https://cryptopals.com/sets/3/challenges/21)
///
/// You can get the psuedocode for this from Wikipedia.
///
/// If you're writing in Python, Ruby, or (gah) PHP, your language is probably already giving you MT19937 as "rand()"; don't use rand(). Write the RNG yourself.
pub fn solve() -> String {
  let mut generator: Rand = random_from_seed(300);
  generator.nth(4).unwrap().to_string()
}
