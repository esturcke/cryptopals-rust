const W: u8 = 32;
const N: usize = 624;
const M: usize = 397;
const R: u8 = 31;
const A: u32 = 0x9908B0DF;
const U: u8 = 11;
const S: u8 = 7;
const B: u32 = 0x9D2C5680;
const T: u8 = 15;
const C: u32 = 0xEFC60000;
const L: u8 = 18;
const F: u32 = 1812433253;
const LOWER_MASK: u32 = (1u32 << R) - 1;
const UPPER_MASK: u32 = !LOWER_MASK;

#[derive(Debug)]
pub struct Rand {
  pub index: usize,
  pub mt: [u32; N],
}

impl Iterator for Rand {
  type Item = u32;

  fn next(&mut self) -> Option<u32> {
    if self.index >= N {
      twist(self);
    }

    let y = self.mt[self.index];
    self.index += 1;

    Some(temper(y))
  }
}

pub fn random_from_seed(seed: u32) -> Rand {
  let mut rand = Rand {
    index: N,
    mt: [0u32; N],
  };
  rand.seed(seed);
  rand
}

impl Rand {
  pub fn seed(&mut self, seed: u32) {
    self.mt[0] = seed;
    for i in 1usize..N {
      self.mt[i] = F.wrapping_mul(self.mt[i - 1] ^ (self.mt[i - 1] >> (W - 2))) + i as u32;
    }
  }
}

pub fn temper(x: u32) -> u32 {
  let mut y = x;
  y ^= y >> U;
  y ^= (y << S) & B;
  y ^= (y << T) & C;
  y ^= y >> L;
  y
}

pub fn untemper(y: u32) -> u32 {
  let mut x = y;
  reverse_right(&mut x, L);
  reverse_left(&mut x, T, C);
  reverse_left(&mut x, S, B);
  reverse_right(&mut x, U);
  x
}

fn reverse_left(x: &mut u32, n: u8, mask: u32) {
  for i in 0..32 {
    *x ^= (*x << n) & (1 << i) & mask;
  }
}

fn reverse_right(x: &mut u32, n: u8) {
  for i in (0..32).rev() {
    *x ^= (*x >> n) & (1 << i);
  }
}

// Generate next N values
fn twist(rand: &mut Rand) {
  for i in 0..N {
    let x = (rand.mt[i] & UPPER_MASK) | rand.mt[(i + 1) % N] & LOWER_MASK;
    let x = if x & 0x1 == 0 { x >> 1 } else { (x >> 1) ^ A };
    rand.mt[i] = rand.mt[(i + M) % N] ^ x;
  }
  rand.index = 0;
}
