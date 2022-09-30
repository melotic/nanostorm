use alloc::vec::Vec;
use bincode::{Decode, Encode};
use hashbrown::HashMap;

use crate::{jump_data::JumpData, VirtAddr};

#[derive(Debug)]
pub struct JumpDataTable {
    table: HashMap<VirtAddr, JumpData>,
}

impl Decode for JumpDataTable {
    fn decode<D: bincode::de::Decoder>(
        decoder: &mut D,
    ) -> Result<Self, bincode::error::DecodeError> {
        let vec = Vec::<(VirtAddr, JumpData)>::decode(decoder)?;
        let mut hashmap = HashMap::with_capacity(vec.len());

        for (key, value) in vec {
            hashmap.insert(key, value);
        }

        Ok(Self { table: hashmap })
    }
}

impl Encode for JumpDataTable {
    fn encode<E: bincode::enc::Encoder>(
        &self,
        encoder: &mut E,
    ) -> Result<(), bincode::error::EncodeError> {
        let mut vec = Vec::with_capacity(self.table.len());
        for (addr, data) in self.table.iter() {
            vec.push((*addr, *data));
        }
        vec.encode(encoder)
    }
}

impl JumpDataTable {
    pub fn new() -> Self {
        Self {
            table: HashMap::new(),
        }
    }

    pub fn insert(&mut self, vaddr: VirtAddr, jump_data: JumpData) {
        self.table.insert(vaddr, jump_data);
    }

    pub fn get(&self, vaddr: VirtAddr) -> Option<&JumpData> {
        self.table.get(&vaddr)
    }
}

impl Default for JumpDataTable {
    fn default() -> Self {
        Self::new()
    }
}
