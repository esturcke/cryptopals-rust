use num_bigint::*;
use num_primes::Generator;

/// # Implement unpadded message recovery oracle
///
/// [Set 6 / Challenge 41](https://cryptopals.com/sets/6/challenges/41)
///
/// Nate Lawson says we should stop calling it "RSA padding" and start calling it "RSA armoring". Here's why.
///
/// Imagine a web application, again with the Javascript encryption, taking RSA-encrypted messages which (again: Javascript) aren't padded before encryption at all.
///
/// You can submit an arbitrary RSA blob and the server will return plaintext. But you can't submit the same message twice: let's say the server keeps hashes of previous messages for some liveness interval, and that the message has an embedded timestamp:
///
/// ```
/// {
///   time: 1356304276,
///   social: '555-55-5555',
/// }
/// ```
///
/// This turns out to be trivially breakable:
///
///   - Capture the ciphertext C
///   - Let N and E be the public modulus and exponent respectively
///   - Let S be a random number > 1 mod N. Doesn't matter what.
///   - Now:
///
///     ```
///     C' = ((S**E mod N) C) mod N
///     ```
///
///   - Submit C', which appears totally different from C, to the server, recovering P', which appears totally different from P
///   - Now:
///
///     ```
///           P'
///     P = -----  mod N
///           S
///     ```
///
///  Oops!
///
/// Implement that attack.
///
/// ## Careful about division in cyclic groups.
///
/// Remember: you don't simply divide mod N; you multiply by the multiplicative inverse mod N. So you'll need a modinv() function.
pub async fn solve() {
  let m = "ahoy, hoy!";
  let (server, c) = Server::setup(&encode(m));

  let s = BigInt::from(123);
  let c2 = (s.modpow(&server.e, &server.n) * &c) % &server.n;
  let m2 = server.decrypt(&c2);

  let m_cracked = m2 * invmod(&s, &server.n) % &server.n;

  assert_eq!(m, decode(&m_cracked));
}

struct Server {
  n: BigInt,
  e: BigInt,
  d: BigInt,
}

impl Server {
  fn setup(m: &BigInt) -> (Server, BigInt) {
    let (n, e, d) = pick_keys();
    let c = m.modpow(&e, &n);
    (Server { n, e, d }, c)
  }

  fn decrypt(&self, c: &BigInt) -> BigInt {
    c.modpow(&self.d, &self.n)
  }
}

fn encode(m: &str) -> BigInt {
  BigInt::from_bytes_be(Sign::Plus, &m.as_bytes())
}

fn decode(m: &BigInt) -> String {
  String::from_utf8(m.to_bytes_be().1).unwrap()
}

fn pick_keys() -> (BigInt, BigInt, BigInt) {
  loop {
    let p = BigInt::from_bytes_be(Sign::Plus, &Generator::new_prime(512).to_bytes_be());
    let q = BigInt::from_bytes_be(Sign::Plus, &Generator::new_prime(512).to_bytes_be());
    let n = &p * &q;
    let et = (&p - 1) * (&q - 1); // totient
    let e = BigInt::from(3);
    let d = invmod(&e, &et);

    if d != BigInt::from(1) {
      break (n, e, d);
    }
  }
}

fn invmod(a: &BigInt, m: &BigInt) -> BigInt {
  let mut nm = (a.clone(), m.clone());
  let mut yx = (BigInt::from(1), BigInt::from(0));

  while nm.0 != BigInt::from(0) {
    yx = (yx.1 - (&nm.1 / &nm.0) * &yx.0, yx.0);
    nm = (&nm.1 % &nm.0, nm.0);
  }

  while yx.1 < BigInt::from(0) {
    yx.1 += m;
  }
  yx.1
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn mod_inv() {
    assert_eq!(
      invmod(&BigInt::from(42), &BigInt::from(2017)),
      BigInt::from(1969)
    );

    assert_eq!(
      invmod(&BigInt::from(17), &BigInt::from(3120)),
      BigInt::from(2753)
    );
  }
}
