use crate::{
    device::{
        CtrlRbDescCommonHeader, CtrlRbDescOpcode, ToCardCtrlRbDesc, ToCardCtrlRbDescUpdateMrTable,
    },
    Device, Error, Pd,
};
use rand::RngCore as _;
use std::{
    hash::{Hash, Hasher},
    mem,
    sync::atomic::{AtomicU32, Ordering},
};

const MR_IDX_BITS: usize = 10;
static NEXT_MR_IDX: AtomicU32 = AtomicU32::new(0);

#[derive(Debug, Clone)]
pub struct Mr {
    pub(crate) handle: u32,
    pub(crate) pd: Pd,
    pub(crate) addr: *const u8,
    pub(crate) len: usize,
    pub(crate) acc_flags: u16,
    pub(crate) lkey: u32,
    #[allow(unused)]
    pub(crate) rkey: u32,
}

pub(crate) struct MrCtx {}

unsafe impl Send for Mr {}
unsafe impl Sync for Mr {}

impl Device {
    pub fn reg_mr(&self, pd: Pd, addr: *const u8, len: usize, acc_flags: u16) -> Result<Mr, Error> {
        let mut mr_pool = self.0.mr.lock().unwrap();
        let mut pd_pool = self.0.pd.lock().unwrap();

        let key_idx =
            NEXT_MR_IDX.fetch_add(1, Ordering::AcqRel) << (mem::size_of::<u32>() * 8 - MR_IDX_BITS);
        let key_secret = rand::thread_rng().next_u32() >> MR_IDX_BITS;

        let key = key_idx | key_secret;

        let mr = Mr {
            handle: rand::thread_rng().next_u32(),
            pd,
            addr,
            len,
            acc_flags,
            lkey: key,
            rkey: key,
        };

        let pd_ctx = pd_pool.get_mut(&mr.pd).ok_or(Error::InvalidPd)?;

        let id = super::get_ctrl_op_id();

        let desc_header = CtrlRbDescCommonHeader {
            valid: true,
            opcode: CtrlRbDescOpcode::UpdateMrTable,
            extra_segment_cnt: 0,
            is_success_or_need_signal_cplt: false,
            user_data: id,
        };

        let desc = ToCardCtrlRbDesc::UpdateMrTable(ToCardCtrlRbDescUpdateMrTable {
            common_header: desc_header,
            base_va: mr.addr as u64,
            mr_length: mr.len as u32,
            mr_key: key,
            pd_handler: mr.pd.handle,
            acc_flags: mr.acc_flags as u8,
            pgt_offset: 0,
        });

        let res = self.do_ctrl_op(id, desc)?;

        if !res {
            return Err(Error::DeviceReturnFailed);
        }

        let pd_res = pd_ctx.mr.insert(mr.clone());
        let mr_res = mr_pool.insert(mr.clone(), MrCtx {});

        assert!(pd_res);
        assert!(mr_res.is_none());

        Ok(mr)
    }

    pub fn dereg_mr(&self, mr: Mr) -> Result<(), Error> {
        let mut mr_pool = self.0.mr.lock().unwrap();
        let mut pd_pool = self.0.pd.lock().unwrap();

        if !mr_pool.contains_key(&mr) {
            return Err(Error::InvalidMr);
        }

        let pd_ctx = pd_pool.get_mut(&mr.pd).ok_or(Error::InvalidPd)?;

        let id = super::get_ctrl_op_id();

        let desc_header = CtrlRbDescCommonHeader {
            valid: true,
            opcode: CtrlRbDescOpcode::UpdateMrTable,
            extra_segment_cnt: 0,
            is_success_or_need_signal_cplt: false,
            user_data: id,
        };

        let desc = ToCardCtrlRbDesc::UpdateMrTable(ToCardCtrlRbDescUpdateMrTable {
            common_header: desc_header,
            base_va: 0,
            mr_length: 0,
            mr_key: mr.lkey,
            pd_handler: 0,
            acc_flags: 0,
            pgt_offset: 0,
        });

        let res = self.do_ctrl_op(id, desc)?;

        if !res {
            return Err(Error::DeviceReturnFailed);
        }

        pd_ctx.mr.remove(&mr);
        mr_pool.remove(&mr);

        Ok(())
    }
}

impl Hash for Mr {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.handle.hash(state);
    }
}

impl PartialEq for Mr {
    fn eq(&self, other: &Self) -> bool {
        self.handle == other.handle
    }
}

impl Eq for Mr {}
