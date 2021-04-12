use crate::rand::*;
use rand::{thread_rng, Rng};
use std::time::SystemTime;

/// # Crack an MT19937 seed
///
/// [Set 3 / Challenge 22](https://cryptopals.com/sets/3/challenges/22)
///
/// Make sure your MT19937 accepts an integer seed value. Test it (verify that you're getting the same sequence of outputs given a seed).
///
/// Write a routine that performs the following operation:
///
/// Wait a random number of seconds between, I don't know, 40 and 1000.
/// Seeds the RNG with the current Unix timestamp
/// Waits a random number of seconds again.
/// Returns the first 32 bit output of the RNG.
/// You get the idea. Go get coffee while it runs. Or just simulate the passage of time, although you're missing some of the fun of this exercise if you do that.
///
/// From the 32 bit RNG output, discover the seed.
pub async fn solve() {
  // Get the random number with a time-based seed
  let (value, t, seed) = random();

  let mut guess = t;
  loop {
    let mut generator = random_from_seed(guess);
    if generator.next().unwrap() == value {
      break;
    }
    guess -= 1;
  }

  assert_eq!(seed, guess);
}

fn random() -> (u32, u32, u32) {
  // Simulate waiting random number of seconds
  let mut rng = thread_rng();
  let mut t = now() + rng.gen_range(40..1000);
  let seed = t;
  let mut generator: Rand = random_from_seed(seed);
  let value = generator.next().unwrap();
  t += rng.gen_range(40..1000);
  (value, t, seed)
}

fn now() -> u32 {
  SystemTime::now()
    .duration_since(SystemTime::UNIX_EPOCH)
    .unwrap()
    .as_secs() as u32
}
