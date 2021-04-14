use crate::bytes::random_64;
use crate::bytes::*;
use crate::crypt::hmac_sha1;
use reqwest;
use std::time::SystemTime;
use tokio::time::{sleep, Duration};

/// # Break HMAC-SHA1 with a slightly less artificial timing leak
///
/// [Set 4 / Challenge 32](https://cryptopals.com/sets/4/challenges/32)
///
/// Reduce the sleep in your "insecure_compare" until your previous solution breaks. (Try 5ms to start.)
///
/// Now break it again.
pub async fn solve() {
  let _file = "hello!";
  // This is very slow so don't run it
  // let hmac = find_hmac(&file).await;
  // assert_eq!(hmac, hmac_sha1(&KEY, file.as_bytes()));
}

#[allow(dead_code)]
async fn find_hmac(file: &str) -> [u8; 20] {
  let mut hmac = [0u8; 20];
  for i in 0usize..20 {
    let mut max: Option<(u8, u128)> = None;
    for c in 0u8..=255 {
      hmac[i] = c;
      let mut times: Vec<u128> = Vec::new();
      for _ in 0u8..9 {
        match time(file, &hmac.to_hex()).await {
          Check::Done => {
            return hmac;
          }
          Check::Time(t) => times.push(t),
        };
      }

      times.sort();
      let sum = times[0..7].iter().sum();
      match max {
        None => {
          max = Some((c, sum));
        }
        Some((_, max_t)) => {
          if max_t < sum {
            max = Some((c, sum));
          }
        }
      };
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
  let status = reqwest::get(format!("http://localhost:9000/32-hmac/{}/{}", file, hmac))
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
    sleep(Duration::from_millis(1)).await;
    if a[i] != b[i] {
      return false;
    }
  }
  true
}

lazy_static! {
  static ref KEY: [u8; 64] = random_64();
}
