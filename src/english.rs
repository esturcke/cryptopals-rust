fn english_counts(byte: u8) -> i64 {
  // Taken from https://link.springer.com/content/pdf/10.3758%2FBF03195586.pdf
  match byte {
    b'A' => 280937,
    b'a' => 5263779,
    b'B' => 169474,
    b'b' => 866156,
    b'C' => 229363,
    b'c' => 1960412,
    b'D' => 129632,
    b'd' => 2369820,
    b'E' => 138443,
    b'e' => 7741842,
    b'F' => 100751,
    b'f' => 1296925,
    b'G' => 93212,
    b'g' => 1206747,
    b'H' => 123632,
    b'h' => 2955858,
    b'I' => 223312,
    b'i' => 4527332,
    b'J' => 78706,
    b'j' => 65856,
    b'K' => 46580,
    b'k' => 460788,
    b'L' => 106984,
    b'l' => 2553152,
    b'M' => 259474,
    b'm' => 1467376,
    b'N' => 205409,
    b'n' => 4535545,
    b'O' => 105700,
    b'o' => 4729266,
    b'P' => 144239,
    b'p' => 1255579,
    b'Q' => 11659,
    b'q' => 54221,
    b'R' => 146448,
    b'r' => 4137949,
    b'S' => 304971,
    b's' => 4186210,
    b'T' => 325462,
    b't' => 5507692,
    b'U' => 57488,
    b'u' => 1613323,
    b'V' => 31053,
    b'v' => 653370,
    b'W' => 107195,
    b'w' => 1015656,
    b'X' => 7578,
    b'x' => 123577,
    b'Y' => 94297,
    b'y' => 1062040,
    b'Z' => 5610,
    b'z' => 66423,
    b'!' => 2178,
    b'"' => 284671,
    b'#' => 10,
    b'$' => 51572,
    b'%' => 1993,
    b'&' => 6523,
    b'\'' => 1199466,
    b'(' => 53398,
    b')' => 53735,
    b'*' => 20716,
    b'+' => 309,
    b'-' => 252302,
    b'.' => 946136,
    b'/' => 8161,
    b'0' => 546233,
    b'1' => 460946,
    b'2' => 333499,
    b'3' => 187606,
    b'4' => 192528,
    b'5' => 374413,
    b'6' => 153865,
    b'7' => 120094,
    b'8' => 182627,
    b'9' => 282364,
    b':' => 54036,
    b';' => 36727,
    b'<' => 82,
    b'=' => 22,
    b'>' => 83,
    b'?' => 12357,
    b'@' => 1,
    b' ' => 12969250, // estimated 10 x f
    _ => 0,
  }
}

//fn frequency_vector(bytes: &Vec<u8>) -> Vec<f

pub fn score(bytes: &Vec<u8>) -> f64 {
  // Collect byte/letter frequencies
  let mut freq: [u64; 256] = [0; 256];
  for &b in bytes.iter() {
    freq[b as usize] += 1;

    // Hack to fix challenge 20
    if b == b'~' {
      return 0f64;
    }
  }

  // Get total sample counts
  let total = (0u8..=255).map(|c| english_counts(c)).fold(0, |a, b| a + b);

  // Calculate distance from English frequency vector
  let mut sum_dist_squared = 0f64;
  for b in 0..=255 {
    sum_dist_squared += (english_counts(b) as f64 / total as f64
      - (freq[b as usize] as f64) / (bytes.len() as f64))
      .powi(2)
  }
  let distance = sum_dist_squared.sqrt();

  // Score
  1.0 - distance
}
