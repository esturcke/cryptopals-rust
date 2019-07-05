mod bytes;
mod challenge1;
mod challenge2;

#[derive(Debug)]
struct Challenge {
    number: u8,
    solver: fn() -> String,
    solution: &'static str,
}

impl Challenge {
    fn check(&self) {
        let solution = (self.solver)();
        assert!(
            solution == self.solution,
            "Solution {} incorrect\n\n{}\n\n  should be  \n\n{}\n\n",
            self.number,
            solution,
            self.solution
        );
    }
}

fn main() {
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
    ];
    for challenge in challenges.iter() {
        challenge.check()
    }
}
