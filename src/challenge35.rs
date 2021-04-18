use crate::{bytes::*, crypt::*};
use num_bigint::*;
use rand::thread_rng;

/// # Implement DH with negotiated groups, and break with malicious "g" parameters
///
/// [Set 5 / Challenge 35](https://cryptopals.com/sets/5/challenges/35)
///
/// A->B
/// Send "p", "g"
/// B->A
/// Send ACK
/// A->B
/// Send "A"
/// B->A
/// Send "B"
/// A->B
/// Send AES-CBC(SHA1(s)[0:16], iv=random(16), msg) + iv
/// B->A
/// Send AES-CBC(SHA1(s)[0:16], iv=random(16), A's msg) + iv
///
/// Do the MITM attack again, but play with "g". What happens with:
///
/// ```
/// g = 1
/// g = p
/// g = p - 1
/// ```
///
/// Write attacks for each.
///
/// ## When does this ever happen?
///
/// Honestly, not that often in real-world systems. If you can mess with "g", chances are you can mess with something worse. Most systems pre-agree on a static DH group. But the same construction exists in Elliptic Curve Diffie-Hellman, and this becomes more relevant there.
pub async fn solve() {
  // Pick parameters for A
  let p = BigUint::from_bytes_be(
    &"ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff".from_hex()
  );
  let g = BigUint::from(2u8);
  let mut rng = thread_rng();
  let a = rng.gen_biguint_below(&p);
  let a_pub = g.modpow(&a, &p);

  // Talk through M with g = 1
  let (b_pub, b) = M1::setup(&p, &g, &a_pub);
  let s = &b_pub.modpow(&a, &p);
  let iv = random_16();
  let key = &sha1(&s.to_bytes_be()).to_vec()[0..16];
  let ct = encrypt_cbc(&key, &iv, &"hello".as_bytes());
  let (ct, iv) = b.echo(&ct, &iv);
  let pt = decrypt_cbc(key, &iv, &ct).unwrap();
  assert_eq!("hello".as_bytes(), pt);

  // Talk through M with g = p
  let (b_pub, b) = Mp::setup(&p, &g, &a_pub);
  let s = &b_pub.modpow(&a, &p);
  let iv = random_16();
  let key = &sha1(&s.to_bytes_be()).to_vec()[0..16];
  let ct = encrypt_cbc(&key, &iv, &"hello".as_bytes());
  let (ct, iv) = b.echo(&ct, &iv);
  let pt = decrypt_cbc(key, &iv, &ct).unwrap();
  assert_eq!("hello".as_bytes(), pt);

  // Talk through M with g = p - 1
  let (b_pub, b) = Mpm1::setup(&p, &g, &a_pub);
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

struct M1 {
  b: B,
}

impl Echo<'_> for M1 {
  fn setup(p: &BigUint, _g: &BigUint, _a_pub: &BigUint) -> (BigUint, Self) {
    let (b_pub, b) = B::setup(p, &BigUint::from(1u8), &BigUint::from(1u8));
    (b_pub, Self { b })
  }
  fn echo(&self, ct: &[u8], iv: &[u8; 16]) -> (Vec<u8>, [u8; 16]) {
    // check that we can decrypt message
    let key = &sha1(&BigUint::from(1u8).to_bytes_be()).to_vec()[0..16];
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

struct Mp {
  b: B,
}

impl Echo<'_> for Mp {
  fn setup(p: &BigUint, _g: &BigUint, _a_pub: &BigUint) -> (BigUint, Self) {
    let (b_pub, b) = B::setup(p, p, &BigUint::from(0u8));
    (b_pub, Self { b })
  }
  fn echo(&self, ct: &[u8], iv: &[u8; 16]) -> (Vec<u8>, [u8; 16]) {
    // check that we can decrypt message
    let key = &sha1(&BigUint::from(0u8).to_bytes_be()).to_vec()[0..16];
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

struct Mpm1 {
  b: B,
}

impl Echo<'_> for Mpm1 {
  fn setup(p: &BigUint, _g: &BigUint, _a_pub: &BigUint) -> (BigUint, Self) {
    let (_b_pub, b) = B::setup(p, &(p - 1u8), &BigUint::from(1u8));
    // b_pub will be 1 if b is even, p - 1 if b is odd
    // if b_pub is 1, a will derive s = 1, so let's always return that
    (BigUint::from(1u8), Self { b })
  }
  fn echo(&self, ct: &[u8], iv: &[u8; 16]) -> (Vec<u8>, [u8; 16]) {
    // check that we can decrypt message
    let key = &sha1(&BigUint::from(1u8).to_bytes_be()).to_vec()[0..16];
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
