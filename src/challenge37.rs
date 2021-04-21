use crate::{bytes::*, crypt::*};
use num_bigint::*;
use rand::thread_rng;

/// # Break SRP with a zero key
///
/// [Set 5 / Challenge 37](https://cryptopals.com/sets/5/challenges/37)
///
/// Get your SRP working in an actual client-server setting. "Log in" with a valid password using the protocol.
///
/// Now log in without your password by having the client send 0 as its "A" value. What does this to the "S" value that both sides compute?
///
/// Now log in without your password by having the client send N, N*2, &c.
///
/// ## Cryptanalytic MVP award
///
/// Trevor Perrin and Nate Lawson taught us this attack 7 years ago. It is excellent. Attacks on DH are tricky to "operationalize". But this attack uses the same concepts, and results in auth bypass. Almost every implementation of SRP we've ever seen has this flaw; if you see a new one, go look for this bug.
pub async fn solve() {
  // Login with the password
  assert!(login(I, P));

  // Login with 0 public key
  assert!(login_a0(I));

  // Login with N public key
  assert!(login_n(I));

  // Login with N*N public key
  assert!(login_n2(I));
}

fn login(email: &str, password: &str) -> bool {
  let mut rng = thread_rng();
  let a = rng.gen_biguint_below(&N);
  let a_pub = G.modpow(&a, &N);

  let (salt, b_pub, server) = S::login(&email, &a_pub);
  let u = BigUint::from_bytes_be(&sha256(
    &[a_pub.to_bytes_be(), b_pub.to_bytes_be()].concat(),
  ));
  let x = BigUint::from_bytes_be(&sha256(&[&salt, password.as_bytes()].concat()));
  let s = (K.clone() * &*N + &b_pub - &(K.clone() * &G.modpow(&x, &N)))
    .modpow(&(a + &(u.clone() * &x)), &N);
  let key = sha256(&s.to_bytes_be());
  server.check(&hmac_sha256(&key, &salt))
}

fn login_a0(email: &str) -> bool {
  let (salt, _b_pub, server) = S::login(&email, &BigUint::from(0u8));
  let key = sha256(&BigUint::from(0u8).to_bytes_be());
  server.check(&hmac_sha256(&key, &salt))
}

fn login_n(email: &str) -> bool {
  let (salt, _b_pub, server) = S::login(&email, &N);
  let key = sha256(&BigUint::from(0u8).to_bytes_be());
  server.check(&hmac_sha256(&key, &salt))
}

fn login_n2(email: &str) -> bool {
  let (salt, _b_pub, server) = S::login(&email, &(N.clone() * &*N));
  let key = sha256(&BigUint::from(0u8).to_bytes_be());
  server.check(&hmac_sha256(&key, &salt))
}

trait Server {
  fn login(email: &str, a_pub: &BigUint) -> (Vec<u8>, BigUint, Self);
  fn check(&self, hmac: &[u8; SHA256_LENGTH]) -> bool;
}

struct S {
  hmac: [u8; SHA256_LENGTH],
}

impl Server for S {
  fn login(_email: &str, a_pub: &BigUint) -> (Vec<u8>, BigUint, Self) {
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
