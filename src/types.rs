use bitflags::bitflags;
use serde::ser::StdError;
use thiserror::Error;

/// Type for `Imm`
#[derive(Debug, Clone, Copy, Hash)]
pub struct Imm(u32);
impl Imm {
    pub fn new(imm: u32) -> Self {
        Self(imm)
    }

    pub fn get(&self) -> u32 {
        self.0
    }

    pub fn into_be(self) -> u32 {
        self.0.to_be()
    }

    pub fn from_be(val: u32) -> Self {
        Self::new(val.to_le())
    }
}

impl From<u32> for Imm {
    fn from(imm: u32) -> Self {
        Self::new(imm)
    }
}

/// `RKey` and `LKey
#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq, Default)]
pub struct Key(u32);
impl Key {
    pub fn new(key: u32) -> Self {
        Self(key)
    }

    pub fn get(&self) -> u32 {
        self.0
    }

    pub fn into_be(self) -> u32 {
        self.0.to_be()
    }

    pub fn from_be(val: u32) -> Self {
        // the val is already in big endian
        // So we need to convert it to little endian, use `to_be()`
        Self::new(val.to_be())
    }
}

impl From<u32> for Key {
    fn from(key: u32) -> Self {
        Self::new(key)
    }
}

/// Message Sequence Number
pub type Msn = ThreeBytesStruct;

/// Packet Sequence Number
pub type Psn = ThreeBytesStruct;

/// Queue Pair Number
pub type Qpn = ThreeBytesStruct;

#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq, Default)]
pub struct ThreeBytesStruct(u32);

impl ThreeBytesStruct {
    const WIDTH: usize = 24;
    const MASK: u32 = u32::MAX >> (32 - Self::WIDTH);
    const MAX: u32 = Self::MASK + 1;

    pub fn new(key: u32) -> Self {
        Self(key & Self::MASK)
    }

    pub fn get(&self) -> u32 {
        self.0
    }

    pub fn into_be(self) -> u32 {
        // In little endian machine, to_le_bytes() is a no-op. Just get the layout.
        let key = self.0.to_le_bytes();
        // Then we reoder the bytes to big endian
        // Note that the last byte is exceed the 24 bits, any value in it will be ignored
        u32::from_le_bytes([key[2], key[1], key[0], 0])
    }

    pub fn from_be(val: u32) -> Self {
        // get the layout.
        let key = val.to_le_bytes();
        // from_le_bytes is also a no-op in little endian machine.
        // We just use it to convert from [u8;4] to `u32`.
        Self::new(u32::from_le_bytes([key[2], key[1], key[0], 0]))
    }

    pub fn wrapping_add(&mut self, rhs: u32){
        self.0 = (self.0 + rhs) % Self::MAX;
    }
}

impl From<u32> for ThreeBytesStruct {
    fn from(key: u32) -> Self {
        Self::new(key)
    }
}

bitflags! {
    #[derive(Debug,Clone,Copy)]
    pub struct MemAccessTypeFlag: u8 {
        const IbvAccessNoFlags = 0;      // Not defined in rdma-core
        const IbvAccessLocalWrite = 1;   // (1 << 0)
        const IbvAccessRemoteWrite = 2;  // (1 << 1)
        const IbvAccessRemoteRead = 4;   // (1 << 2)
        const IbvAccessRemoteAtomic = 8; // (1 << 3)
        const IbvAccessMwBind = 16;      // (1 << 4)
        const IbvAccessZeroBased = 32;   // (1 << 5)
        const IbvAccessOnDemand = 64;    // (1 << 6)
        const IbvAccessHugetlb = 128;    // (1 << 7)
                                   // IbvAccessRelaxedOrdering   = IBV_ACCESS_OPTIONAL_FIRST,
    }
}

#[derive(Debug, Clone, Copy)]
pub enum QpType {
    Rc = 2,
    Uc = 3,
    Ud = 4,
    RawPacket = 8,
    XrcSend = 9,
    XrcRecv = 10,
}

#[derive(Debug, Clone)]
pub enum Pmtu {
    Mtu256 = 1,
    Mtu512 = 2,
    Mtu1024 = 3,
    Mtu2048 = 4,
    Mtu4096 = 5,
}

impl From<&Pmtu> for u64 {
    fn from(pmtu: &Pmtu) -> u64 {
        match pmtu {
            Pmtu::Mtu256 => 256,
            Pmtu::Mtu512 => 512,
            Pmtu::Mtu1024 => 1024,
            Pmtu::Mtu2048 => 2048,
            Pmtu::Mtu4096 => 4096,
        }
    }
}

impl From<&Pmtu> for u32 {
    fn from(pmtu: &Pmtu) -> u32 {
        match pmtu {
            Pmtu::Mtu256 => 256,
            Pmtu::Mtu512 => 512,
            Pmtu::Mtu1024 => 1024,
            Pmtu::Mtu2048 => 2048,
            Pmtu::Mtu4096 => 4096,
        }
    }
}

pub struct Sge {
    pub addr: u64,
    pub len: u32,
    pub key: Key,
}

#[derive(Debug, Error)]
pub enum Error {
    #[error(transparent)]
    Device(Box<dyn StdError>),
    #[error("device busy")]
    DeviceBusy,
    #[error("device return failed")]
    DeviceReturnFailed,
    #[error("ongoing ctrl cmd ctx lost")]
    CtrlCtxLost,
    #[error("ongoing read ctx lost")]
    ReadCtxLost,
    #[error("ongoing write ctx lost")]
    WriteCtxLost,
    #[error("QP busy")]
    QpBusy,
    #[error("invalid PD handle")]
    InvalidPd,
    #[error("invalid MR handle")]
    InvalidMr,
    #[error("invalid QP handle")]
    InvalidQp,
    #[error("PD in use")]
    PdInUse,
    #[error("QP in use")]
    QpInUse,
    #[error("no available QP")]
    NoAvailableQp,
    #[error("no available MR")]
    NoAvailableMr,
    #[error("allocate page table failed")]
    AllocPageTable,
    #[error("build descriptor failed, lack of `{0}`")]
    BuildDescFailed(&'static str),
}

#[cfg(test)]
mod tests{
    use std::slice::from_raw_parts;
    use crate::types::Psn;

    #[test]
    fn test_wrapping_add(){
        let mut psn = Psn::new(0xffffff);
        psn.wrapping_add(1);
        assert_eq!(psn.get(), 0);

        psn.wrapping_add(2);
        assert_eq!(psn.get(), 2);

        psn.wrapping_add(0xffffff);
        assert_eq!(psn.get(), 1);
    }

    #[test]
    fn test_to_be(){
        let psn = Psn::new(0x123456);
        let mem = psn.into_be();
        let buf = unsafe{
            from_raw_parts(&mem as *const _ as *const u8, 4)
        };
        assert_eq!(buf, &[0x12, 0x34, 0x56, 0]);
        assert_eq!(Psn::from_be(mem).get(), 0x123456);

        let key = crate::types::Key::new(0x12345678);
        let mem = key.into_be();
        let buf = unsafe{
            from_raw_parts(&mem as *const _ as *const u8, 4)
        };
        assert_eq!(buf, &[0x12, 0x34, 0x56, 0x78]);
        assert_eq!(crate::types::Key::from_be(mem).get(), 0x12345678);

    }
}