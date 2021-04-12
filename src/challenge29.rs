use crate::crypt::*;
use rand::seq::SliceRandom;
use std::fs::File;
use std::io::{BufRead, BufReader};

/// # Break a SHA-1 keyed MAC using length extension
///
/// [Set 4 / Challenge 29](https://cryptopals.com/sets/4/challenges/29)
///
/// Break a SHA-1 keyed MAC using length extension
/// Secret-prefix SHA-1 MACs are trivially breakable.
///
/// The attack on secret-prefix SHA1 relies on the fact that you can take the ouput of SHA-1 and use it as a new starting point for SHA-1, thus taking an arbitrary SHA-1 hash and "feeding it more data".
///
/// Since the key precedes the data in secret-prefix, any additional data you feed the SHA-1 hash in this fashion will appear to have been hashed with the secret key.
///
/// To carry out the attack, you'll need to account for the fact that SHA-1 is "padded" with the bit-length of the message; your forged message will need to include that padding. We call this "glue padding". The final message you actually forge will be:
///
/// ```
/// SHA1(key || original-message || glue-padding || new-message)
/// ```
/// (where the final padding on the whole constructed message is implied)
///
/// Note that to generate the glue padding, you'll need to know the original bit length of the message; the message itself is known to the attacker, but the secret key isn't, so you'll need to guess at it.
///
/// This sounds more complicated than it is in practice.
///
/// To implement the attack, first write the function that computes the MD padding of an arbitrary message and verify that you're generating the same padding that your SHA-1 implementation is using. This should take you 5-10 minutes.
///
/// Now, take the SHA-1 secret-prefix MAC of the message you want to forge --- this is just a SHA-1 hash --- and break it into 32 bit SHA-1 registers (SHA-1 calls them "a", "b", "c", &c).
///
/// Modify your SHA-1 implementation so that callers can pass in new values for "a", "b", "c" &c (they normally start at magic numbers). With the registers "fixated", hash the additional data you want to forge.
///
/// Using this attack, generate a secret-prefix MAC under a secret key (choose a random word from /usr/share/dict/words or something) of the string:
///
/// ```
/// "comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon"
/// ```
///
/// Forge a variant of this message that ends with ";admin=true".
///
/// ## This is a very useful attack.
///
/// For instance: Thai Duong and Juliano Rizzo, who got to this attack before we did, used it to break the Flickr API.
pub async fn solve() {
  let (message, mac) = get_message_and_mac();
  let suffix = b";admin=true";
  let (forged_message, forged_mac) = (1..)
    .map(|key_length| {
      let length = key_length + message.len();
      let forged_message: Vec<_> = [
        message,
        &[1u8 << 7],
        &vec![0; 63 - ((length + 8) % 64)][..],
        &(length as u64 * 8).to_be_bytes(),
        suffix,
      ]
      .concat();
      let mut initial = [0u32; 5];
      for (i, word) in mac.chunks(4).enumerate() {
        initial[i] = u32::from_be_bytes([word[0], word[1], word[2], word[3]]);
      }
      let forged_mac = sha1_extend(
        suffix,
        &initial,
        forged_message.len() - suffix.len() + key_length,
      );
      (forged_message, forged_mac)
    })
    .find(|(message, mac)| check_mac(message, mac))
    .expect("to be able to forge");

  assert!(check_mac(&forged_message, &forged_mac));
}

const MESSAGE: &'static [u8] =
  b"comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon";

fn get_message_and_mac() -> (&'static [u8], [u8; 20]) {
  let mac = sha1_mac(&KEY, &MESSAGE);
  (MESSAGE, mac)
}

fn check_mac(message: &[u8], mac: &[u8]) -> bool {
  sha1_mac(&KEY, message) == mac
}

lazy_static! {
  static ref KEY: Vec<u8> = {
    let file = File::open("/usr/share/dict/words").expect("Failed to open dict");
    let lines: Vec<_> = BufReader::new(file)
      .lines()
      .map(|l| l.expect("Can read word"))
      .collect();
    lines
      .choose(&mut rand::thread_rng())
      .expect("")
      .as_bytes()
      .to_vec()
  };
}
