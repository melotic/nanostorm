use bincode::{Decode, Encode};

use crate::jump_type::JumpType;

pub enum Flags {
    Carry = 0x0001,
    Parity = 0x0004,
    Zero = 0x0040,
    Sign = 0x0080,
    Overflow = 0x0800,
}
#[derive(Encode, Decode, Copy, Clone, Debug)]
pub struct JumpData {
    jump_type: JumpType,
    j_false: u8,
    j_true: isize,
}

#[inline]
fn flag(eflags: u64, bit: Flags) -> bool {
    (eflags & (bit as u64)) != 0
}

impl JumpData {
    pub fn new(jump_type: JumpType, size: u8, offset: isize) -> Self {
        Self {
            jump_type,
            j_false: size,
            j_true: offset,
        }
    }

    pub fn eval_jump(&self, eflags: u64, rcx: u64) -> isize {
        // todo check this
        if match self.jump_type {
            JumpType::Jmp => true,
            JumpType::Je => flag(eflags, Flags::Zero),
            JumpType::Jne => !flag(eflags, Flags::Zero),
            JumpType::Jb => flag(eflags, Flags::Carry),
            JumpType::Ja => !flag(eflags, Flags::Carry) && !flag(eflags, Flags::Zero),
            JumpType::Jbe => flag(eflags, Flags::Carry) || flag(eflags, Flags::Zero),
            JumpType::Js => flag(eflags, Flags::Sign),
            JumpType::Jns => !flag(eflags, Flags::Sign),
            JumpType::Jp => flag(eflags, Flags::Parity),
            JumpType::Jnp => !flag(eflags, Flags::Parity),
            JumpType::Jl => flag(eflags, Flags::Sign) != flag(eflags, Flags::Overflow),
            JumpType::Jle => {
                flag(eflags, Flags::Zero)
                    || (flag(eflags, Flags::Sign) != flag(eflags, Flags::Overflow))
            }
            JumpType::Jcxz | JumpType::Jecxz | JumpType::Jrcxz => rcx == 0,
            JumpType::Jae => !flag(eflags, Flags::Carry),
            JumpType::Jg => {
                !flag(eflags, Flags::Zero)
                    && (flag(eflags, Flags::Sign) == flag(eflags, Flags::Overflow))
            }
            JumpType::Jge => flag(eflags, Flags::Sign) == flag(eflags, Flags::Overflow),
            JumpType::Jmpe => false,
            JumpType::Jno => !flag(eflags, Flags::Overflow),
            JumpType::Jo => flag(eflags, Flags::Overflow),
        } {
            self.j_true
        } else {
            self.j_false as isize
        }
    }
}
