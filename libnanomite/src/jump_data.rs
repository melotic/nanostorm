use bincode::{Decode, Encode};

use crate::jump_type::JumpType;

pub struct RflagsBits;

impl RflagsBits {
    pub const OF: u64 = 0x0000_0001;

    pub const SF: u64 = 0x0000_0002;

    pub const ZF: u64 = 0x0000_0004;

    pub const CF: u64 = 0x0000_0010;

    pub const PF: u64 = 0x0000_0020;
}

#[derive(Encode, Decode, Copy, Clone, Debug)]
pub struct JumpData {
    jump_type: JumpType,
    j_false: u8,
    j_true: isize,
}

#[inline]
fn flag(eflags: u64, bit: u64) -> bool {
    (eflags & bit) != 0
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
            JumpType::Je => flag(eflags, RflagsBits::ZF),
            JumpType::Jne => !flag(eflags, RflagsBits::ZF),
            JumpType::Jb => flag(eflags, RflagsBits::CF),
            JumpType::Ja => !flag(eflags, RflagsBits::CF) && !flag(eflags, RflagsBits::ZF),
            JumpType::Jbe => flag(eflags, RflagsBits::CF) || flag(eflags, RflagsBits::ZF),
            JumpType::Js => flag(eflags, RflagsBits::SF),
            JumpType::Jns => !flag(eflags, RflagsBits::SF),
            JumpType::Jp => flag(eflags, RflagsBits::PF),
            JumpType::Jnp => !flag(eflags, RflagsBits::PF),
            JumpType::Jl => flag(eflags, RflagsBits::SF) != flag(eflags, RflagsBits::OF),
            JumpType::Jle => {
                flag(eflags, RflagsBits::ZF)
                    || (flag(eflags, RflagsBits::SF) != flag(eflags, RflagsBits::OF))
            }
            JumpType::Jcxz | JumpType::Jecxz | JumpType::Jrcxz => rcx == 0,
            JumpType::Jae => !flag(eflags, RflagsBits::CF),
            JumpType::Jg => {
                !flag(eflags, RflagsBits::ZF)
                    && (flag(eflags, RflagsBits::SF) == flag(eflags, RflagsBits::OF))
            }
            JumpType::Jge => flag(eflags, RflagsBits::SF) == flag(eflags, RflagsBits::OF),
            JumpType::Jmpe => false,
            JumpType::Jno => !flag(eflags, RflagsBits::OF),
            JumpType::Jo => flag(eflags, RflagsBits::OF),
        } {
            self.j_true
        } else {
            self.j_false as isize
        }
    }
}
