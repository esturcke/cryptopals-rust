#[macro_use]
extern crate lazy_static;

mod bytes;
mod challenge1;
mod challenge10;
mod challenge11;
mod challenge12;
mod challenge13;
mod challenge14;
mod challenge15;
mod challenge16;
mod challenge17;
mod challenge18;
mod challenge19;
mod challenge2;
mod challenge20;
mod challenge21;
mod challenge3;
mod challenge4;
mod challenge5;
mod challenge6;
mod challenge7;
mod challenge8;
mod challenge9;

mod crack;
mod crypt;
mod english;
mod rand;
use std::fs;

#[derive(Debug)]
struct Challenge<'a> {
    number: u8,
    solver: fn() -> String,
    solution: &'a str,
}

impl<'a> Challenge<'a> {
    fn check(&self) {
        let solution = (self.solver)();
        if solution != self.solution {
            println!(
                "Solution {} is wrong\n\n{}\n{:?}\n\n    should be\n\n{}\n{:?}\n\n",
                self.number,
                solution,
                solution.as_bytes(),
                self.solution,
                self.solution.as_bytes()
            );
        }
    }
}

fn main() {
    let vanilla = fs::read_to_string("data/play-that-funky-music.txt").expect("Can't load lyrics");
    let ice_ice_baby = fs::read_to_string("data/ice-ice-baby.txt").expect("Can't load lyrics");
    let fury = fs::read_to_string("data/fury.txt").expect("Can't load lyrics");

    let challenges = [
        Challenge {
            number: 1,
            solver: challenge1::solve,
            solution: "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t",
        },
        Challenge {
            number: 2,
            solver: challenge2::solve,
            solution: "746865206b696420646f6e277420706c6179",
        },
        Challenge {
            number: 3,
            solver: challenge3::solve,
            solution: "Cooking MC's like a pound of bacon",
        },
        Challenge {
            number: 4,
            solver: challenge4::solve,
            solution: "Now that the party is jumping\n",
        },
        Challenge {
            number: 5,
            solver: challenge5::solve,
            solution: "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f",
        },
        Challenge {
            number: 6,
            solver: challenge6::solve,
            solution: &vanilla,
        },
        Challenge {
            number: 7,
            solver: challenge7::solve,
            solution: &vanilla,
        },
        Challenge {
            number: 8,
            solver: challenge8::solve,
            solution: "d880619740a8a19b7840a8a31c810a3d08649af70dc06f4fd5d2d69c744cd283e2dd052f6b641dbf9d11b0348542bb5708649af70dc06f4fd5d2d69c744cd2839475c9dfdbc1d46597949d9c7e82bf5a08649af70dc06f4fd5d2d69c744cd28397a93eab8d6aecd566489154789a6b0308649af70dc06f4fd5d2d69c744cd283d403180c98c8f6db1f2a3f9c4040deb0ab51b29933f2c123c58386b06fba186a",
        },
        Challenge {
            number: 9,
            solver: challenge9::solve,
            solution: "YELLOW SUBMARINE\x04\x04\x04\x04",
        },
        Challenge {
            number: 10,
            solver: challenge10::solve,
            solution: &vanilla,
        },
        Challenge {
            number: 11,
            solver: challenge11::solve,
            solution: "done",
        },
        Challenge {
            number: 12,
            solver: challenge12::solve,
            solution: &ice_ice_baby,
        },
        Challenge {
            number: 13,
            solver: challenge13::solve,
            solution: "admin",
        },
        Challenge {
            number: 14,
            solver: challenge14::solve,
            solution: &ice_ice_baby,
        },
        Challenge {
            number: 15,
            solver: challenge15::solve,
            solution: "done",
        },
        Challenge {
            number: 16,
            solver: challenge16::solve,
            solution: "true",
        },
        Challenge {
            number: 17,
            solver: challenge17::solve,
            solution: "yay",
        },
        Challenge {
            number: 18,
            solver: challenge18::solve,
            solution: "Yo, VIP Let's kick it Ice, Ice, baby Ice, Ice, baby ",
        },
        Challenge {
            number: 19,
            solver: challenge19::solve,
            solution: "yay",
        },
        Challenge {
            number: 20,
            solver: challenge20::solve,
            solution: &fury,
        },
        Challenge {
            number: 21,
            solver: challenge21::solve,
            solution: "1585191914",
        },
    ];
    for challenge in challenges.iter() {
        challenge.check()
    }
}
