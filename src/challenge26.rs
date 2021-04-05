use crate::bytes::*;
use crate::crypt::*;

/// # CTR bitflipping
///
/// [Set 4 / Challenge 26](https://cryptopals.com/sets/4/challenges/26)
///
/// There are people in the world that believe that CTR resists bit flipping attacks of the kind to which CBC mode is susceptible.
///
/// Re-implement the CBC bitflipping exercise from earlier to use CTR mode instead of CBC mode. Inject an "admin=true" token.
pub fn solve() -> String {
  let mut ct = encrypt(&[255u8; 11]);
  let block = xor(&not(&ct[32..43]), ";admin=true".as_bytes());
  for (i, byte) in block.iter().enumerate() {
    ct[32 + i] = *byte;
  }
  assert_eq!(get_admin(&ct), "true");
  String::from("yay")
}

lazy_static! {
  static ref KEY: [u8; 16] = random_16();
  static ref NONCE: [u8; 8] = random_8();
}

fn encrypt(user_data: &[u8]) -> Vec<u8> {
  encrypt_ctr(
    &KEY[..],
    &NONCE,
    &[
      "comment1=cooking%20MCs;userdata=".as_bytes(),
      user_data,
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
  let query = decrypt_ctr(&KEY[..], &NONCE, &ct)
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
