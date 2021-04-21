use crate::{bytes::*, crypt::*};
use num_bigint::*;
use rand::thread_rng;

/// # Implement Secure Remote Password (SRP)
///
/// [Set 5 / Challenge 36](https://cryptopals.com/sets/5/challenges/36)
///
/// To understand SRP, look at how you generate an AES key from DH; now, just observe you can do the "opposite" operation an generate a numeric parameter from a hash. Then:
///
/// Replace A and B with C and S (client & server)
///
/// C & S
/// Agree on N=[NIST Prime], g=2, k=3, I (email), P (password)
/// S
///   1. Generate salt as random integer
///   2. Generate string xH=SHA256(salt|password)
///   3. Convert xH to integer x somehow (put 0x on hexdigest)
///   4. Generate v=g**x % N
///   5. Save everything but x, xH
/// C->S
///   1. Send I, A=g**a % N (a la Diffie Hellman)
/// S->C
///   1. Send salt, B=kv + g**b % N
/// S, C
///   1. Compute string uH = SHA256(A|B), u = integer of uH
/// C
///   1. Generate string xH=SHA256(salt|password)
///   2. Convert xH to integer x somehow (put 0x on hexdigest)
///   3. Generate S = (B - k * g**x)**(a + u * x) % N
///   4. Generate K = SHA256(S)
/// S
///   1. Generate S = (A * v**u) ** b % N
///   2. Generate K = SHA256(S)
/// C->S
///   1 .Send HMAC-SHA256(K, salt)
/// S->C
///   1. Send "OK" if HMAC-SHA256(K, salt) validates
///
/// You're going to want to do this at a REPL of some sort; it may take a couple tries.
///
/// It doesn't matter how you go from integer to string or string to integer (where things are going in or out of SHA256) as long as you do it consistently. I tested by using the ASCII decimal representation of integers as input to SHA256, and by converting the hexdigest to an integer when processing its output.
///
/// This is basically Diffie Hellman with a tweak of mixing the password into the public keys. The server also takes an extra step to avoid storing an easily crackable password-equivalent.
pub async fn solve() {
  let mut rng = thread_rng();
  let a = rng.gen_biguint_below(&N);
  let a_pub = G.modpow(&a, &N);

  let (salt, b_pub, server) = S::setup(&I, &a_pub);
  let u = BigUint::from_bytes_be(&sha256(
    &[a_pub.to_bytes_be(), b_pub.to_bytes_be()].concat(),
  ));
  let x = BigUint::from_bytes_be(&sha256(&[&salt, P.as_bytes()].concat()));
  let s = (K.clone() * &*N + &b_pub - &(K.clone() * &G.modpow(&x, &N))).modpow(&(a + &(u.clone() * &x)), &N);
  let key = sha256(&s.to_bytes_be());
  let hmac = hmac_sha256(&key, &salt);
  assert!(server.check(&hmac));
}

trait Server {
  fn setup(email: &str, a_pub: &BigUint) -> (Vec<u8>, BigUint, Self);
  fn check(&self, hmac: &[u8; SHA256_LENGTH]) -> bool;
}

struct S {
  hmac: [u8; SHA256_LENGTH],
}

impl Server for S {
  fn setup(_email: &str, a_pub: &BigUint) -> (Vec<u8>, BigUint, Self) {
    let salt = random_bytes(2);
    let x = BigUint::from_bytes_be(&sha256(&[&salt, P.as_bytes()].concat()));
    let v = G.modpow(&x, &N);

    let mut rng = thread_rng();
    let b = rng.gen_biguint_below(&N);
    let b_pub = G.modpow(&b, &N) + &v * &*K;

    let u = BigUint::from_bytes_be(&sha256(
      &[a_pub.to_bytes_be(), b_pub.to_bytes_be()].concat(),
    ));
    let s = (a_pub * v.modpow(&u.clone(), &N)).modpow(&b, &N);
    let key = sha256(&s.to_bytes_be());
    let hmac = hmac_sha256(&key, &salt);
    (salt.clone(), b_pub, S { hmac })
  }

  fn check(&self, hmac: &[u8; SHA256_LENGTH]) -> bool {
    hmac == &self.hmac
  }
}

// Email and password
const I: &'static str = "itme@example.com";
const P: &'static str = "123456";

lazy_static! {
  // DH parameters
  static ref N: BigUint = BigUint::from_bytes_be(
    &"ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff".from_hex()
  );
  static ref G: BigUint = BigUint::from(2u8);
  static ref K:BigUint = BigUint::from(3u8);
}
