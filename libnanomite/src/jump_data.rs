use bincode::{Decode, Encode};

use crate::jump_type::JumpType;

pub enum Flags {
    CarryFlag = 0x0001,
    ParityFlag = 0x0004,
    AdjustFlag = 0x0010,
    ZeroFlag = 0x0040,
    SignFlag = 0x0080,
    TrapFlag = 0x0100,
    InterruptEnableFlag = 0x0200,
    DirectionFlag = 0x0400,
    OverflowFlag = 0x0800,
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
            JumpType::Je => flag(eflags, Flags::ZeroFlag),
            JumpType::Jne => !flag(eflags, Flags::ZeroFlag),
            JumpType::Jb => flag(eflags, Flags::CarryFlag),
            JumpType::Ja => !flag(eflags, Flags::CarryFlag) && !flag(eflags, Flags::ZeroFlag),
            JumpType::Jbe => flag(eflags, Flags::CarryFlag) || flag(eflags, Flags::ZeroFlag),
            JumpType::Js => flag(eflags, Flags::SignFlag),
            JumpType::Jns => !flag(eflags, Flags::SignFlag),
            JumpType::Jp => flag(eflags, Flags::ParityFlag),
            JumpType::Jnp => !flag(eflags, Flags::ParityFlag),
            JumpType::Jl => flag(eflags, Flags::SignFlag) != flag(eflags, Flags::OverflowFlag),
            JumpType::Jle => {
                flag(eflags, Flags::ZeroFlag)
                    || (flag(eflags, Flags::SignFlag) != flag(eflags, Flags::OverflowFlag))
            }
            JumpType::Jcxz | JumpType::Jecxz | JumpType::Jrcxz => rcx == 0,
            JumpType::Jae => !flag(eflags, Flags::CarryFlag),
            JumpType::Jg => {
                !flag(eflags, Flags::ZeroFlag)
                    && (flag(eflags, Flags::SignFlag) == flag(eflags, Flags::OverflowFlag))
            }
            JumpType::Jge => flag(eflags, Flags::SignFlag) == flag(eflags, Flags::OverflowFlag),
            JumpType::Jmpe => false,
            JumpType::Jno => !flag(eflags, Flags::OverflowFlag),
            JumpType::Jo => flag(eflags, Flags::OverflowFlag),
        } {
            self.j_true
        } else {
            self.j_false as isize
        }
    }
}
