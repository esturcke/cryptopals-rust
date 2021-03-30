use crate::bytes::*;
use crate::crypt::*;
use std::collections::HashMap;

/// # ECB cut-and-paste
///
/// [Set 2 / Challenge 13](https://cryptopals.com/sets/2/challenges/13)
///
/// Write a k=v parsing routine, as if for a structured cookie. The routine should take:
///
/// ```
/// foo=bar&baz=qux&zap=zazzle
/// ```
///
/// ... and produce:
///
/// ```
/// {
///   foo: 'bar',
///   baz: 'qux',
///   zap: 'zazzle'
/// }
/// ```
///
/// (you know, the object; I don't care if you convert it to JSON).
///
/// Now write a function that encodes a user profile in that format, given an email address. You should have something like:
///
/// ```
/// profile_for("foo@bar.com")
/// ```
///
/// ... and it should produce:
///
/// ```
/// {
///   email: 'foo@bar.com',
///   uid: 10,
///   role: 'user'
/// }
///```
///
/// ... encoded as:
///
/// ```
/// email=foo@bar.com&uid=10&role=user
/// ```
///
/// Your "profile_for" function should not allow encoding metacharacters (& and =). Eat them, quote them, whatever you want to do, but don't let people set their email address to "foo@bar.com&role=admin".
///
/// Now, two more easy functions. Generate a random AES key, then:
///
///   A. Encrypt the encoded user profile under the key; "provide" that to the "attacker".
///   B. Decrypt the encoded user profile and parse it.
///
///Using only the user input to profile_for() (as an oracle to generate "valid" ciphertexts) and the ciphertexts themselves, make a role=admin profile.
pub fn solve() -> String {
  // Get the ct for a user profile, with "user" in a block by itself
  let ct_user = encrypted_profile("a@example.com");

  // Figure out what the ct for "admin" should be. The `<-buffer->` aligns
  // admin to the start of a block with PKCS7 padding
  let ct_role = encrypted_profile(&["<-buffer->", "admin", &vec![11; 11][..].as_string()].concat());

  // Chop off the user role and add admin role
  let ct = [&ct_user[..ct_user.len() - 16], &ct_role[16..32]].concat();

  // Return role
  String::from(parse(&decrypt(&ct).as_string()).get("role").unwrap())
}

fn parse(query: &str) -> HashMap<String, String> {
  let mut user = HashMap::new();
  for field in query.split('&') {
    let mut parts = field.split('=');
    user.insert(
      String::from(parts.next().unwrap()),
      String::from(parts.next().unwrap()),
    );
  }
  user
}

fn profile_for(email: &str) -> String {
  let mut sanitized_email = String::from(email);
  sanitized_email.retain(|c| c != '&' && c != '=');
  format!("email={}&uid=10&role=user", sanitized_email)
}

lazy_static! {
  static ref KEY: Vec<u8> = random_bytes(16);
}

fn encrypt(pt: &[u8]) -> Vec<u8> {
  encrypt_ecb(&KEY, pt)
}

fn decrypt(ct: &[u8]) -> Vec<u8> {
  decrypt_ecb(&KEY, ct)
}

fn encrypted_profile(email: &str) -> Vec<u8> {
  return encrypt(&profile_for(email).as_bytes());
}
