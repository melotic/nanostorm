use bincode::{Encode, Decode};

#[derive(Encode, Decode, Copy, Clone)]
pub enum JumpType {
    Ja,
    Jae,
    Jb,
    Jbe,
    Jcxz,
    Je,
    Jecxz,
    Jg,
    Jge,
    Jl,
    Jle,
    Jmp,
    Jmpe,
    Jne,
    Jno,
    Jnp,
    Jns,
    Jo,
    Jp,
    Jrcxz,
    Js,
}

impl rand::prelude::Distribution<JumpType> for rand::distributions::Standard {
    fn sample<R: rand::Rng + ?Sized>(&self, rng: &mut R) -> JumpType {
        match rng.gen_range(0..=20) {
            0 => JumpType::Ja,
            1 => JumpType::Jae,
            2 => JumpType::Jb,
            3 => JumpType::Jbe,
            4 => JumpType::Jcxz,
            5 => JumpType::Je,
            6 => JumpType::Jecxz,
            7 => JumpType::Jg,
            8 => JumpType::Jge,
            9 => JumpType::Jl,
            10 => JumpType::Jle,
            11 => JumpType::Jmp,
            12 => JumpType::Jmpe,
            13 => JumpType::Jne,
            14 => JumpType::Jno,
            15 => JumpType::Jnp,
            16 => JumpType::Jns,
            17 => JumpType::Jo,
            18 => JumpType::Jp,
            19 => JumpType::Jrcxz,
            20 => JumpType::Js,
            _ => unreachable!(),
        }
    }
}
