use crate::{bytes::EncodedBytes, crypt::*};
use num_bigint::{BigUint, RandBigInt};
use rand::{thread_rng, Rng};

/// # Implement Diffie-Hellman
///
/// [Set 5 / Challenge 33](https://cryptopals.com/sets/5/challenges/33)
///
/// For one of the most important algorithms in cryptography this exercise couldn't be a whole lot easier.
///
/// Set a variable "p" to 37 and "g" to 5. This algorithm is so easy I'm not even going to explain it. Just do what I do.
///
/// Generate "a", a random number mod 37. Now generate "A", which is "g" raised to the "a" power mode 37 --- A = (g**a) % p.
///
/// Do the same for "b" and "B".
///
/// "A" and "B" are public keys. Generate a session key with them; set "s" to "B" raised to the "a" power mod 37 --- s = (B**a) % p.
///
/// Do the same with A**b, check that you come up with the same "s".
///
/// To turn "s" into a key, you can just hash it to create 128 bits of key material (or SHA256 it to create a key for encrypting and a key for a MAC).
///
/// Ok, that was fun, now repeat the exercise with bignums like in the real world. Here are parameters NIST likes:
///
/// ```
/// p:
/// ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024
/// e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd
/// 3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec
/// 6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f
/// 24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361
/// c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552
/// bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff
/// fffffffffffff
///
/// g: 2
/// ```
///
/// This is very easy to do in Python or Ruby or other high-level languages that auto-promote fixnums to bignums, but it isn't "hard" anywhere.
///
/// Note that you'll need to write your own modexp (this is blackboard math, don't freak out), because you'll blow out your bignum library raising "a" to the 1024-bit-numberth power. You can find modexp routines on Rosetta Code for most languages.
pub async fn solve() {
  // Part 1: Small parameters

  let mut rng = thread_rng();
  let p = 37u128;
  let g = 5u128;

  // Generate public keys
  let a = rng.gen_range(0..37);
  let a_pub = g.pow(a) % p;
  let b = rng.gen_range(0..37);
  let b_pub = g.pow(b) % p;

  // Generate session key
  let _key = sha1(&u128::to_le_bytes(b_pub.pow(a) % p));
  let _key = sha1(&u128::to_le_bytes(a_pub.pow(b) % p));

  // Part 2: Large parameters

  let mut rng = thread_rng();
  let p = BigUint::from_bytes_be(
    &"ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff".from_hex()
  );
  let g = BigUint::from(2u128);

  // Generate public keys
  let a = rng.gen_biguint_below(&p);
  let a_pub = g.modpow(&a, &p);
  let b = rng.gen_biguint_below(&p);
  let b_pub = g.modpow(&b, &p);

  // Generate session key
  let key1 = sha1(&b_pub.modpow(&a, &p).to_bytes_be());
  let key2 = sha1(&a_pub.modpow(&b, &p).to_bytes_be());
  assert_eq!(key1, key2);
}
