use crate::{bytes::*, crypt::*};
use num_bigint::{BigUint, RandBigInt};
use rand::thread_rng;

/// # Implement a MITM key-fixing attack on Diffie-Hellman with parameter injection
///
/// [Set 5 / Challenge 34](https://cryptopals.com/sets/5/challenges/34)
///
/// Use the code you just worked out to build a protocol and an "echo" bot. You don't actually have to do the network part of this if you don't want; just simulate that. The protocol is:
///
/// A->B
/// Send "p", "g", "A"
/// B->A
/// Send "B"
/// A->B
/// Send AES-CBC(SHA1(s)[0:16], iv=random(16), msg) + iv
/// B->A
/// Send AES-CBC(SHA1(s)[0:16], iv=random(16), A's msg) + iv
/// (In other words, derive an AES key from DH with SHA1, use it in both directions, and do CBC with random IVs appended or prepended to the message).
///
/// Now implement the following MITM attack:
///
/// A->M
/// Send "p", "g", "A"
/// M->B
/// Send "p", "g", "p"
/// B->M
/// Send "B"
/// M->A
/// Send "p"
/// A->M
/// Send AES-CBC(SHA1(s)[0:16], iv=random(16), msg) + iv
/// M->B
/// Relay that to B
/// B->M
/// Send AES-CBC(SHA1(s)[0:16], iv=random(16), A's msg) + iv
/// M->A
/// Relay that to A
/// M should be able to decrypt the messages. "A" and "B" in the protocol --- the public keys, over the wire --- have been swapped out with "p". Do the DH math on this quickly to see what that does to the predictability of the key.
///
/// Decrypt the messages from M's vantage point as they go by.
///
/// Note that you don't actually have to inject bogus parameters to make this attack work; you could just generate Ma, MA, Mb, and MB as valid DH parameters to do a generic MITM attack. But do the parameter injection attack; it's going to come up again.
pub async fn solve() {
  // Talk to B directly
  let mut rng = thread_rng();
  let p = BigUint::from_bytes_be(
    &"ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff".from_hex()
  );
  let g = BigUint::from(2u128);
  let a = rng.gen_biguint_below(&p);
  let a_pub = g.modpow(&a, &p);
  let (b_pub, b) = B::setup(&p, &g, &a_pub);
  let s = &b_pub.modpow(&a, &p);
  let iv = random_16();
  let key = &sha1(&s.to_bytes_be()).to_vec()[0..16];
  let ct = encrypt_cbc(&key, &iv, &"hello".as_bytes());

  let (ct, iv) = b.echo(&ct, &iv);
  let pt = decrypt_cbc(key, &iv, &ct).unwrap();

  assert_eq!("hello".as_bytes(), pt);

  // Talk through M
  let (b_pub, b) = M::setup(&p, &g, &a_pub);
  let s = &b_pub.modpow(&a, &p);
  let iv = random_16();
  let key = &sha1(&s.to_bytes_be()).to_vec()[0..16];
  let ct = encrypt_cbc(&key, &iv, &"hello".as_bytes());

  let (ct, iv) = b.echo(&ct, &iv);
  let pt = decrypt_cbc(key, &iv, &ct).unwrap();

  assert_eq!("hello".as_bytes(), pt);
}

trait Echo<'a> {
  fn setup(p: &BigUint, g: &BigUint, a_pub: &BigUint) -> (BigUint, Self);
  fn echo(&self, ct: &[u8], iv: &[u8; 16]) -> (Vec<u8>, [u8; 16]);
}

struct B {
  s: BigUint,
}

impl Echo<'_> for B {
  fn setup(p: &BigUint, g: &BigUint, a_pub: &BigUint) -> (BigUint, Self) {
    let mut rng = thread_rng();
    let b = rng.gen_biguint_below(&p);
    let b_pub = g.modpow(&b, &p);
    let s = &a_pub.modpow(&b, &p);
    (b_pub, Self { s: s.clone() })
  }
  fn echo(&self, ct: &[u8], iv: &[u8; 16]) -> (Vec<u8>, [u8; 16]) {
    let key = &sha1(&(self.s.to_bytes_be())).to_vec()[0..16];
    let pt = decrypt_cbc(&key, iv, ct).unwrap();

    // Encrypt with new IV
    let iv = random_16();
    let ct = encrypt_cbc(&key, &iv, &pt);
    (ct, iv)
  }
}

struct M {
  b: B,
}

impl Echo<'_> for M {
  fn setup(p: &BigUint, g: &BigUint, _a_pub: &BigUint) -> (BigUint, Self) {
    let (_, b) = B::setup(p, g, p);
    (p.clone(), Self { b })
  }
  fn echo(&self, ct: &[u8], iv: &[u8; 16]) -> (Vec<u8>, [u8; 16]) {
    // check that we can decrypt message
    let key = &sha1(&[0u8]).to_vec()[0..16];
    let pt = decrypt_cbc(&key, iv, ct).unwrap();
    assert_eq!("hello".as_bytes(), pt);

    // pass along and check we can decrypt response
    let (ct, iv) = self.b.echo(ct, iv);
    let pt = decrypt_cbc(&key, &iv, &ct).unwrap();
    assert_eq!("hello".as_bytes(), pt);

    // pass back response from b
    (ct, iv)
  }
}
