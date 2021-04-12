use crate::bytes::*;
use crate::crypt::*;

/// # Recover the key from CBC with IV=Key
///
/// [Set 4 / Challenge 27](https://cryptopals.com/sets/4/challenges/27)
///
/// Take your code from the CBC exercise and modify it so that it repurposes the key for CBC encryption as the IV.
///
/// Applications sometimes use the key as an IV on the auspices that both the sender and the receiver have to know the key already, and can save some space by using it as both a key and an IV.
///
/// Using the key as an IV is insecure; an attacker that can modify ciphertext in flight can get the receiver to decrypt a value that will reveal the key.
///
/// The CBC code from exercise 16 encrypts a URL string. Verify each byte of the plaintext for ASCII compliance (ie, look for high-ASCII values). Noncompliant messages should raise an exception or return an error that includes the decrypted plaintext (this happens all the time in real systems, for what it's worth).
///
/// Use your code to encrypt a message that is at least 3 blocks long:
///
/// ```
/// AES-CBC(P_1, P_2, P_3) -> C_1, C_2, C_3
/// ```
///
/// Modify the message (you are now the attacker):
///
/// ```
/// C_1, C_2, C_3 -> C_1, 0, C_1
/// ```
///
/// Decrypt the message (you are now the receiver) and raise the appropriate error if high-ASCII is found.
///
/// As the attacker, recovering the plaintext from the error, extract the key:
///
/// ```
/// P'_1 XOR P'_3
/// ```
pub async fn solve() {
  let ct = encrypt(&[255u8; 16]);
  let ct = [&ct[0..16], &[0u8; 16], &ct[0..16], &ct[48..]].concat();
  let key = match check_ct(&ct) {
    Ok(_) => panic!("the disco"),
    Err(pt) => xor(&pt[0..16], &pt[32..48]),
  };

  assert_eq!(KEY[..], key);
}

lazy_static! {
  static ref KEY: [u8; 16] = random_16();
}

fn encrypt(user_data: &[u8]) -> Vec<u8> {
  encrypt_cbc(
    &KEY[..],
    &KEY[..],
    &[
      "comment1=cooking%20MCs;userdata=".as_bytes(),
      &escape(user_data),
      ";comment2=%20like%20a%20pound%20of%20bacon".as_bytes(),
    ]
    .concat(),
  )
}

fn escape(string: &[u8]) -> Vec<u8> {
  string
    .iter()
    .flat_map(|&x| match x as char {
      ';' => "%3B".as_bytes().to_vec(),
      '=' => "%3D".as_bytes().to_vec(),
      _ => [x as u8].to_vec(),
    })
    .collect()
}

fn check_ct(ct: &[u8]) -> Result<(), Vec<u8>> {
  let pt = decrypt_cbc(&KEY[..], &KEY[..], &ct).expect("can decrypt");
  if pt.clone().into_iter().any(|b| b > 127) {
    Err(pt)
  } else {
    Ok(())
  }
}
