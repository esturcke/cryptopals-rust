use crate::bytes::random_64;
use crate::bytes::*;
use crate::crypt::hmac_sha1;
use reqwest;
use std::time::SystemTime;
use tokio::time::{sleep, Duration};

/// # Implement and break HMAC-SHA1 with an artificial timing leak
///
/// [Set 4 / Challenge 31](https://cryptopals.com/sets/4/challenges/31)
///
/// The psuedocode on Wikipedia should be enough. HMAC is very easy.
///
/// Using the web framework of your choosing (Sinatra, web.py, whatever), write a tiny application that has a URL that takes a "file" argument and a "signature" argument, like so:
///
/// ```
/// http://localhost:9000/test?file=foo&signature=46b4ec586117154dacd49d664e5d63fdc88efb51
/// ```
///
/// Have the server generate an HMAC key, and then verify that the "signature" on incoming requests is valid for "file", using the "==" operator to compare the valid MAC for a file with the "signature" parameter (in other words, verify the HMAC the way any normal programmer would verify it).
///
/// Write a function, call it "insecure_compare", that implements the == operation by doing byte-at-a-time comparisons with early exit (ie, return false at the first non-matching byte).
///
/// In the loop for "insecure_compare", add a 50ms sleep (sleep 50ms after each byte).
///
/// Use your "insecure_compare" function to verify the HMACs on incoming requests, and test that the whole contraption works. Return a 500 if the MAC is invalid, and a 200 if it's OK.
///
/// Using the timing leak in this application, write a program that discovers the valid MAC for any file.
///
/// ## Why artificial delays?
///
/// Early-exit string compares are probably the most common source of cryptographic timing leaks, but they aren't especially easy to exploit. In fact, many timing leaks (for instance, any in C, C++, Ruby, or Python) probably aren't exploitable over a wide-area network at all. To play with attacking real-world timing leaks, you have to start writing low-level timing code. We're keeping things cryptographic in these challenges.
pub async fn solve() {
  let _file = "hello!";
  // This is very slow so don't run it
  // let hmac = find_hmac(&file).await;
  // assert_eq!(hmac, hmac_sha1(&KEY, file.as_bytes()));
}

#[allow(dead_code)]
async fn find_hmac(file: &str) -> [u8; 20] {
  let mut hmac = [0u8; 20];
  for i in 0..20 {
    let mut max: Option<(u8, u128)> = None;
    for c in 0u8..=255 {
      hmac[i] = c;
      match time(file, &hmac.to_hex()).await {
        Check::Done => {
          return hmac;
        }
        Check::Time(t) => {
          match max {
            None => {
              max = Some((c, t));
            }
            Some((_, max_t)) => {
              if max_t < t {
                max = Some((c, t));
              }
            }
          };
        }
      }
    }
    hmac[i] = max.unwrap().0;
  }
  hmac
}

enum Check {
  Done,
  Time(u128),
}

async fn time(file: &str, hmac: &str) -> Check {
  let start = SystemTime::now();
  let status = reqwest::get(format!("http://localhost:9000/31-hmac/{}/{}", file, hmac))
    .await
    .unwrap()
    .status()
    .as_u16();
  match status {
    200 => Check::Done,
    500 => Check::Time(SystemTime::now().duration_since(start).unwrap().as_micros()),
    _ => panic!("Unexpected status code {}", status),
  }
}

pub async fn check(file: String, hmac: String) -> bool {
  slow_equals(&hmac_sha1(&KEY, file.as_bytes()), &hmac.from_hex()).await
}

async fn slow_equals(a: &[u8], b: &[u8]) -> bool {
  if a.len() != b.len() {
    return false;
  }
  for i in 0..a.len() {
    sleep(Duration::from_millis(50)).await;
    if a[i] != b[i] {
      return false;
    }
  }
  true
}

lazy_static! {
  static ref KEY: [u8; 64] = random_64();
}
