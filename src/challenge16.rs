use crate::bytes::*;
use crate::crypt::*;

/// # CBC bitflipping attacks
///
/// [Set 2 / Challenge 16](https://cryptopals.com/sets/2/challenges/16)
///
/// Generate a random AES key.
///
/// Combine your padding code and CBC code to write two functions.
///
/// The first function should take an arbitrary input string, prepend the string:
///
/// ```
/// "comment1=cooking%20MCs;userdata="
/// ```
///
/// .. and append the string:
///
/// ```
/// ";comment2=%20like%20a%20pound%20of%20bacon"
/// ```
///
/// The function should quote out the ";" and "=" characters.
///
/// The function should then pad out the input to the 16-byte AES block length and encrypt it under the random AES key.
///
/// The second function should decrypt the string and look for the characters ";admin=true;" (or, equivalently, decrypt, split the string on ";", convert each resulting string into 2-tuples, and look for the "admin" tuple).
///
/// Return true or false based on whether the string exists.
///
/// If you've written the first function properly, it should not be possible to provide user input to it that will generate the string the second function is looking for. We'll have to break the crypto to do that.
///
/// Instead, modify the ciphertext (without knowledge of the AES key) to accomplish this.
///
/// You're relying on the fact that in CBC mode, a 1-bit error in a ciphertext block:
///
///   - Completely scrambles the block the error occurs in
///   - Produces the identical 1-bit error(/edit) in the next ciphertext block.
///
/// ## Stop and think for a second.
///
/// Before you implement this attack, answer this question: why does CBC mode have this property?
pub fn solve() -> String {
  let mut ct = encrypt(&[0u8; 32]);
  let block = xor(&ct[32..48], "<--->;admin=true".as_bytes());
  for (i, byte) in block.iter().enumerate() {
    ct[32 + i] = *byte;
  }
  get_admin(&ct)
}

lazy_static! {
  static ref KEY: Vec<u8> = random_bytes(16);
  static ref IV: Vec<u8> = random_bytes(16);
}

fn encrypt(user_data: &[u8]) -> Vec<u8> {
  encrypt_cbc(
    &KEY,
    &IV,
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

fn get_admin(ct: &[u8]) -> String {
  let query = decrypt_cbc(&KEY, &IV, &ct)
    .expect("Correct padding")
    .into_iter()
    .filter(|&x| x < 128)
    .collect::<Vec<u8>>()
    .as_string();
  for field in query.split(';') {
    let mut parts = field.split('=');
    if let (Some("admin"), Some(value)) = (parts.next(), parts.next()) {
      return String::from(value);
    }
  }
  String::from("")
}
