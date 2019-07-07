fn english_frequency(byte: u8) -> f64 {
    match byte {
        b'a' => 0.0651738,
        b'b' => 0.0124248,
        b'c' => 0.0217339,
        b'd' => 0.0349835,
        b'e' => 0.1041442,
        b'f' => 0.0197881,
        b'g' => 0.0158610,
        b'h' => 0.0492888,
        b'i' => 0.0558094,
        b'j' => 0.0009033,
        b'k' => 0.0050529,
        b'l' => 0.0331490,
        b'm' => 0.0202124,
        b'n' => 0.0564513,
        b'o' => 0.0596302,
        b'p' => 0.0137645,
        b'q' => 0.0008606,
        b'r' => 0.0497563,
        b's' => 0.0515760,
        b't' => 0.0729357,
        b'u' => 0.0225134,
        b'v' => 0.0082903,
        b'w' => 0.0171272,
        b'x' => 0.0013692,
        b'y' => 0.0145984,
        b'z' => 0.0007836,
        b' ' => 0.1918182,
        _ => 0.0,
    }
}

//fn frequency_vector(bytes: &Vec<u8>) -> Vec<f

pub fn score(bytes: &Vec<u8>) -> f64 {
    // Collect byte/letter frequencies
    let mut freq: [u64; 256] = [0; 256];
    for &b in bytes.iter() {
        freq[b as usize] += 1;
    }

    // Calculate distance from English frequency vector
    let mut sum_dist_squared = 0f64;
    for b in 0..=255 {
        sum_dist_squared +=
            (english_frequency(b) - (freq[b as usize] as f64) / (bytes.len() as f64)).powi(2)
    }
    let distance = sum_dist_squared.sqrt();

    // Score
    1.0 - distance
}
