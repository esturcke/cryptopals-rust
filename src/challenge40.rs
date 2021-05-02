use num_bigint::*;
use num_primes::Generator;

/// # Implement an E=3 RSA Broadcast attack
///
/// [Set 5 / Challenge 40](https://cryptopals.com/sets/5/challenges/40)
///
/// Assume you're a Javascript programmer. That is, you're using a naive handrolled RSA to encrypt without padding.
///
/// Assume you can be coerced into encrypting the same plaintext three times, under three different public keys. You can; it's happened.
///
/// Then an attacker can trivially decrypt your message, by:
///
/// Capturing any 3 of the ciphertexts and their corresponding pubkeys
/// Using the CRT to solve for the number represented by the three ciphertexts (which are residues mod their respective pubkeys)
/// Taking the cube root of the resulting number
/// The CRT says you can take any number and represent it as the combination of a series of residues mod a series of moduli. In the three-residue case, you have:
///
/// ```
/// result =
///   (c_0 * m_s_0 * invmod(m_s_0, n_0)) +
///   (c_1 * m_s_1 * invmod(m_s_1, n_1)) +
///   (c_2 * m_s_2 * invmod(m_s_2, n_2)) mod N_012
/// ```
///
/// where:
///
/// ```
///  c_0, c_1, c_2 are the three respective residues mod
///  n_0, n_1, n_2
///
///  m_s_n (for n in 0, 1, 2) are the product of the moduli
///  EXCEPT n_n --- ie, m_s_1 is n_0 * n_2
///
///  N_012 is the product of all three moduli
/// ```
///
/// To decrypt RSA using a simple cube root, leave off the final modulus operation; just take the raw accumulated result and cube-root it.
pub async fn solve() {
  let m = "ahoy, hoy!";

  let (c1, n1) = encrypt(m);
  let (c2, n2) = encrypt(m);
  let (c3, n3) = encrypt(m);

  let ms1 = &n2 * &n3;
  let ms2 = &n1 * &n3;
  let ms3 = &n1 * &n2;

  let result = ((&c1 * &ms1 * invmod(&ms1, &n1))
    + (&c2 * &ms2 * invmod(&ms2, &n2))
    + (&c3 * &ms3 * invmod(&ms3, &n3)))
    % (&n1 * &n2 * &n3);

  assert_eq!(m, decode(&result.cbrt()));
}

fn encrypt(m: &str) -> (BigInt, BigInt) {
  let (n, e, _d) = pick_keys();
  let c = encode(m).modpow(&e, &n);
  (c, n)
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
