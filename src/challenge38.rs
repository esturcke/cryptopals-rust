use crate::english::*;
use crate::{bytes::*, crypt::*};
use num_bigint::*;
use rand::prelude::*;
use rand::thread_rng;

/// # Offline dictionary attack on simplified SRP
///
/// [Set 5 / Challenge 38](https://cryptopals.com/sets/5/challenges/38)
///
/// **S**
///
/// ```
/// x = SHA256(salt|password)
/// v = g**x % n
/// ```
///
/// **C -> S**
///
/// ```
/// I, A = g**a % n
/// ```
///
/// **S -> C**
///
/// ```
/// salt, B = g**b % n, u = 128 bit random number
/// ```
///
/// **C**
///
/// ```
/// x = SHA256(salt|password)
/// S = B**(a + ux) % n
/// K = SHA256(S)
/// ```
///
/// **S**
///
/// ```
/// S = (A * v ** u)**b % n
/// K = SHA256(S)
/// ```
///
/// **C -> S**
///
/// ```
/// HMAC-SHA256(K, salt)
/// ```
///
/// **S -> C**
///
/// ```
/// Send "OK" if HMAC-SHA256(K, salt) validates
/// ```
///
/// Note that in this protocol, the server's "B" parameter doesn't depend on the password (it's just a Diffie Hellman public key).
///
/// Make sure the protocol works given a valid password.
///
/// Now, run the protocol as a MITM attacker: pose as the server and use arbitrary values for b, B, u, and salt.
///
/// Crack the password from A's HMAC-SHA256(K, salt).
pub async fn solve() {
  // Login with the password
  assert!(login(I, &P));

  // Login with the password via MitM
  assert!(login_mitm(I, &P));
}

fn login(email: &str, password: &str) -> bool {
  let mut rng = thread_rng();
  let a = rng.gen_biguint_below(&N);
  let a_pub = G.modpow(&a, &N);

  let (salt, b_pub, u, server) = S::login(&email, &a_pub);
  let x = BigUint::from_bytes_be(&sha256(&[&salt, password.as_bytes()].concat()));
  let s = b_pub.modpow(&(a + &x * u), &N);
  let key = sha256(&s.to_bytes_be());
  server.check(&hmac_sha256(&key, &salt))
}

fn login_mitm(email: &str, password: &str) -> bool {
  let mut rng = thread_rng();
  let a = rng.gen_biguint_below(&N);
  let a_pub = G.modpow(&a, &N);

  let (salt, b_pub, u, server) = M::login(&email, &a_pub);
  let x = BigUint::from_bytes_be(&sha256(&[&salt, password.as_bytes()].concat()));
  let s = b_pub.modpow(&(a + &x * u), &N);
  let key = sha256(&s.to_bytes_be());
  server.check(&hmac_sha256(&key, &salt))
}

trait Server {
  fn login(email: &str, a_pub: &BigUint) -> (Vec<u8>, BigUint, u128, Self);
  fn check(&self, hmac: &[u8; SHA256_LENGTH]) -> bool;
}

struct M {
  server: S,

  // From actual server
  b_pub: BigUint,
  u: u128,
  salt: Vec<u8>,

  // From client
  a_pub: BigUint,

  // MitM a
  mitm_a: BigUint,
}

impl Server for M {
  fn login(email: &str, a_pub: &BigUint) -> (Vec<u8>, BigUint, u128, Self) {
    let mut rng = thread_rng();
    let mitm_a = rng.gen_biguint_below(&N);
    let mitm_a_pub = G.modpow(&mitm_a, &N);
    let (salt, b_pub, u, server) = Server::login(email, &mitm_a_pub);
    let m = M {
      server,
      b_pub,
      u,
      salt: salt.clone(),
      a_pub: a_pub.clone(),
      mitm_a,
    };

    (salt, G.modpow(&BigUint::from(1u8), &N), 1u128, m)
  }

  fn check(&self, hmac: &[u8; SHA256_LENGTH]) -> bool {
    // Crack password
    // We can use a dictionary attack using A's method of computing
    // the HMAC by choosing b so we don't need to know a:
    // s = B^(a + ux)         % n
    //   = (g^b)^(a + ux)     % n
    //   = (g^b)^a * (g^b)^ux % n
    //   = (g^a)^b * g^bux    % n
    //   = A^b * g^bux        % n
    //   = A * g^x            % n   with b = 1, u = 1

    let password = words()
      .iter()
      .find(|&word| {
        let x = BigUint::from_bytes_be(&sha256(&[&self.salt, word.as_bytes()].concat()));
        let s = (G.modpow(&x, &N) * &self.a_pub) % &*N;
        let k = sha256(&s.to_bytes_be());
        hmac == &hmac_sha256(&k, &self.salt)
      })
      .unwrap();

    // Check that we guessed the password
    assert_eq!(&*P, password);

    // Construct hmac with original parameters
    let x = BigUint::from_bytes_be(&sha256(&[&self.salt, password.as_bytes()].concat()));
    let s = self.b_pub.modpow(&(&self.mitm_a + &x * self.u), &N);
    let k = sha256(&s.to_bytes_be());
    self.server.check(&hmac_sha256(&k, &self.salt))
  }
}

struct S {
  hmac: [u8; SHA256_LENGTH],
}

impl Server for S {
  fn login(_email: &str, a_pub: &BigUint) -> (Vec<u8>, BigUint, u128, Self) {
    let salt = random_bytes(2);
    let x = BigUint::from_bytes_be(&sha256(&[&salt, P.as_bytes()].concat()));
    let v = G.modpow(&x, &N);

    let mut rng = thread_rng();
    let b = rng.gen_biguint_below(&N);
    let b_pub = G.modpow(&b, &N);

    let u: u128 = random();
    let s = (a_pub * v.modpow(&BigUint::from(u), &N)).modpow(&b, &N);
    let key = sha256(&s.to_bytes_be());
    let hmac = hmac_sha256(&key, &salt);
    (salt, b_pub, u, S { hmac })
  }

  fn check(&self, hmac: &[u8; SHA256_LENGTH]) -> bool {
    hmac == &self.hmac
  }
}

// Email and password
const I: &'static str = "itme@example.com";

lazy_static! {
  // DH parameters
  static ref N: BigUint = BigUint::from_bytes_be(
    &"ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff".from_hex()
  );
  static ref G: BigUint = BigUint::from(2u8);
  static ref K: BigUint = BigUint::from(3u8);
  static ref P: String = {
    words()
      .choose(&mut rand::thread_rng())
      .expect("").clone()
  };
}
