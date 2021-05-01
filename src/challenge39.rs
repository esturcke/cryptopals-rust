use num_bigint::*;
use num_primes::Generator;

/// # Implement RSA
///
/// [Set 5 / Challenge 39](https://cryptopals.com/sets/5/challenges/39)
///
/// There are two annoying things about implementing RSA. Both of them involve key generation; the actual encryption/decryption in RSA is trivial.
///
/// First, you need to generate random primes. You can't just agree on a prime ahead of time, like you do in DH. You can write this algorithm yourself, but I just cheat and use OpenSSL's BN library to do the work.
///
/// The second is that you need an "invmod" operation (the multiplicative inverse), which is not an operation that is wired into your language. The algorithm is just a couple lines, but I always lose an hour getting it to work.
///
/// I recommend you not bother with primegen, but do take the time to get your own EGCD and invmod algorithm working.
///
/// Now:
///
/// Generate 2 random primes. We'll use small numbers to start, so you can just pick them out of a prime table. Call them "p" and "q".
/// Let n be p * q. Your RSA math is modulo n.
/// Let et be (p-1)*(q-1) (the "totient"). You need this value only for keygen.
/// Let e be 3.
/// Compute d = invmod(e, et). invmod(17, 3120) is 2753.
/// Your public key is [e, n]. Your private key is [d, n].
/// To encrypt: c = m**e%n. To decrypt: m = c**d%n
/// Test this out with a number, like "42".
/// Repeat with bignum primes (keep e=3).
/// Finally, to encrypt a string, do something cheesy, like convert the string to hex and put "0x" on the front of it to turn it into a number. The math cares not how stupidly you feed it strings.
pub async fn solve() {
  let (n, e, d) = pick_keys();
  let m = "ahoy, hoy!";
  let c = encode(m).modpow(&e, &n);
  let m2 = decode(&c.modpow(&d, &n));

  assert_eq!(m, m2);
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
