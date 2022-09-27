use bincode::{Decode, Encode};

use crate::jump_type::JumpType;

#[derive(Encode, Decode, Copy, Clone)]
pub struct JumpData {
    jump_type: JumpType,
    j_false: u8,
    j_true: isize,
}

impl JumpData {
    pub fn new(jump_type: JumpType, size: u8, offset: isize) -> Self {
        Self {
            jump_type,
            j_false: size,
            j_true: offset,
        }
    }

    pub fn eval_jump(&self, eflags: usize, rcx: usize) -> isize {
        // todo check this
        if match self.jump_type {
            JumpType::Ja => eflags & 0x1 == 0x1,
            JumpType::Jae => eflags & 0x1 == 0x1 || eflags & 0x40 == 0x40,
            JumpType::Jb => eflags & 0x1 == 0x0,
            JumpType::Jbe => eflags & 0x1 == 0x0 || eflags & 0x40 == 0x40,
            JumpType::Jcxz | JumpType::Jecxz | JumpType::Jrcxz => rcx == 0,
            JumpType::Je => eflags & 0x40 == 0x40,
            JumpType::Jg => eflags & 0x1 == 0x1 && eflags & 0x40 == 0x0,
            JumpType::Jge => eflags & 0x1 == 0x1 || eflags & 0x40 == 0x0,
            JumpType::Jl => eflags & 0x1 == 0x0 && eflags & 0x40 == 0x40,
            JumpType::Jle => eflags & 0x1 == 0x0 || eflags & 0x40 == 0x40,
            JumpType::Jmp => true,
            JumpType::Jmpe => true,
            JumpType::Jne => eflags & 0x40 == 0x0,
            JumpType::Jno => eflags & 0x4 == 0x0,
            JumpType::Jnp => eflags & 0x8 == 0x0,
            JumpType::Jns => eflags & 0x2 == 0x0,
            JumpType::Jo => eflags & 0x4 == 0x4,
            JumpType::Jp => eflags & 0x8 == 0x8,
            JumpType::Js => eflags & 0x2 == 0x2,
        } {
            self.j_true
        } else {
            self.j_false as isize
        }
    }
}
