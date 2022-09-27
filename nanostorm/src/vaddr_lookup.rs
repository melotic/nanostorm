use color_eyre::{eyre::ContextCompat, Result};
use goblin::{elf::Elf, pe::PE};
use libnanomite::VirtAddr;

/// A trait for objects that can translate virtual addresses to file offset addresses.
pub trait VirtualAddressor {
    fn virtual_address(&self, vaddr: usize) -> Result<VirtAddr>;
}

pub struct PeVirtualAddressor<'a> {
    pe: PE<'a>,
}

impl<'a> PeVirtualAddressor<'a> {
    pub fn new(pe: PE<'a>) -> PeVirtualAddressor<'a> {
        Self { pe }
    }
}

impl VirtualAddressor for PeVirtualAddressor<'_> {
    fn virtual_address(&self, vaddr: usize) -> Result<VirtAddr> {
        // Find the section the vaddr is in, then calculate the offset
        let vaddr = vaddr - 0x10000000;

        let section = self
            .pe
            .sections
            .iter()
            .find(|s| {
                vaddr >= s.virtual_address as usize
                    && vaddr < (s.virtual_address + s.virtual_size) as usize
            })
            .wrap_err_with(|| format!("Could not find section for vaddr: {:#x}", vaddr))?;

        Ok(vaddr - section.virtual_address as usize + section.pointer_to_raw_data as usize)
    }
}

pub struct ElfVirtualAddressor<'a> {
    elf: goblin::elf::Elf<'a>,
}

impl<'a> ElfVirtualAddressor<'a> {
    pub fn new(elf: Elf<'a>) -> ElfVirtualAddressor<'a> {
        Self { elf }
    }
}

impl VirtualAddressor for ElfVirtualAddressor<'_> {
    fn virtual_address(&self, vaddr: usize) -> Result<VirtAddr> {
        let vaddr = vaddr - 0x100000;

        // find the section that contains the vaddr
        let section = self
            .elf
            .section_headers
            .iter()
            .find(|s| vaddr >= s.sh_addr as usize && vaddr < (s.sh_addr + s.sh_size) as usize)
            .wrap_err_with(|| format!("Could not find section for vaddr: {:#x}", vaddr))?;

        Ok(vaddr - section.sh_addr as usize + section.sh_offset as usize)
    }
}
