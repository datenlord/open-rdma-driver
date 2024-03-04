use crate::{
    device::{
        ToCardCtrlRbDesc, ToCardCtrlRbDescCommon, ToCardCtrlRbDescUpdateMrTable,
        ToCardCtrlRbDescUpdatePageTable,
    },
    Device, Error, Pd,
};
use rand::RngCore as _;
use std::{
    hash::{Hash, Hasher},
    mem, ptr,
};

#[derive(Debug, Clone)]
pub struct Mr {
    pub(crate) key: u32,
}

impl Mr {
    pub fn get_key(&self) -> u32 {
        self.key
    }
}

#[allow(unused)]
pub(crate) struct MrCtx {
    pub(crate) key: u32,
    pub(crate) pd: Pd,
    pub(crate) va: u64,
    pub(crate) len: u32,
    pub(crate) acc_flags: u8,
    pub(crate) pgt_offset: usize,
    pub(crate) pg_size: u32,
}

pub(crate) struct MrPgt {
    table: [u64; crate::MR_PGT_SIZE],
    free_blk_list: *mut MrPgtFreeBlk,
}

struct MrPgtFreeBlk {
    idx: usize,
    len: usize,
    prev: *mut Self,
    next: *mut Self,
}

impl Device {
    pub fn reg_mr(
        &self,
        pd: Pd,
        addr: u64,
        len: u32,
        pg_size: u32,
        acc_flags: u8,
    ) -> Result<Mr, Error> {
        // FIXME: must call mlock to lock the pages, prevent form being swapped out.
        let mut mr_table = self.0.mr_table.lock().unwrap();
        let mut pd_pool = self.0.pd.lock().unwrap();

        let mut mr_pgt = self.0.mr_pgt.lock().unwrap();

        let Some(mr_idx) = mr_table
            .iter()
            .enumerate()
            .find_map(|(idx, ctx)| ctx.is_none().then_some(idx))
        else {
            return Err(Error::NoAvailableMr);
        };

        let pd_ctx = pd_pool.get_mut(&pd).ok_or(Error::InvalidPd)?;

        let pgte_cnt = len.div_ceil(pg_size) as usize;
        let pgt_offset = mr_pgt.alloc(pgte_cnt)?;

        for pgt_idx in 0..pgte_cnt {
            let va = addr + (pg_size as usize * pgt_idx) as u64;
            let pa = self.0.adaptor.get_phys_addr(va as usize);
            mr_pgt.table[pgt_offset + pgt_idx] = pa as u64;
        }

        let op_id = super::get_ctrl_op_id();

        let desc = ToCardCtrlRbDesc::UpdatePageTable(ToCardCtrlRbDescUpdatePageTable {
            common: ToCardCtrlRbDescCommon { op_id },
            start_addr: self.0.adaptor.get_phys_addr(mr_pgt.table.as_ptr() as usize) as u64,
            pgt_idx: pgt_offset as u32,
            pgte_cnt: pgte_cnt as u32,
        });

        let res = self.do_ctrl_op(op_id, desc)?;

        if !res {
            mr_pgt.dealloc(pgt_offset, pgte_cnt);
            return Err(Error::DeviceReturnFailed);
        }

        let key_idx = (mr_idx as u32) << (mem::size_of::<u32>() * 8 - crate::MR_KEY_IDX_BIT_CNT);
        let key_secret = rand::thread_rng().next_u32() >> crate::MR_KEY_IDX_BIT_CNT;
        let key = key_idx | key_secret;

        let mr = Mr { key };
        let mr_ctx = MrCtx {
            key,
            pd,
            va: addr,
            len,
            acc_flags,
            pgt_offset,
            pg_size,
        };

        let op_id = super::get_ctrl_op_id();

        let desc = ToCardCtrlRbDesc::UpdateMrTable(ToCardCtrlRbDescUpdateMrTable {
            common: ToCardCtrlRbDescCommon { op_id },
            addr,
            len,
            key,
            pd_hdl: mr_ctx.pd.handle,
            acc_flags,
            pgt_offset: pgt_offset as u32,
        });

        let res = self.do_ctrl_op(op_id, desc)?;

        if !res {
            return Err(Error::DeviceReturnFailed);
        }

        mr_table[mr_idx] = Some(mr_ctx);

        let pd_res = pd_ctx.mr.insert(mr.clone());
        assert!(pd_res);

        Ok(mr)
    }

    pub fn dereg_mr(&self, mr: Mr) -> Result<(), Error> {
        let mut mr_table = self.0.mr_table.lock().unwrap();
        let mut pd_pool = self.0.pd.lock().unwrap();

        let mut mr_pgt = self.0.mr_pgt.lock().unwrap();

        let mr_idx = mr.key >> (mem::size_of::<u32>() * 8 - crate::MR_KEY_IDX_BIT_CNT);

        let Some(mr_ctx) = mr_table[mr_idx as usize].as_mut() else {
            return Err(Error::InvalidMr);
        };

        let pd_ctx = pd_pool.get_mut(&mr_ctx.pd).ok_or(Error::InvalidPd)?;

        let op_id = super::get_ctrl_op_id();

        // let desc_header = CtrlRbDescCommonHeader {
        //     valid: true,
        //     opcode: CtrlRbDescOpcode::UpdateMrTable,
        //     extra_segment_cnt: 0,
        //     is_success_or_need_signal_cplt: false,
        //     user_data: ctrl_op_id,
        // };

        // let desc = ToCardCtrlRbDesc::UpdateMrTable(ToCardCtrlRbDescUpdateMrTable {
        //     common_header: desc_header,
        //     base_va: 0,
        //     mr_length: 0,
        //     mr_key: mr.key,
        //     pd_handler: 0,
        //     acc_flags: 0,
        //     pgt_offset: 0,
        // });

        let desc = ToCardCtrlRbDesc::UpdateMrTable(ToCardCtrlRbDescUpdateMrTable {
            common: ToCardCtrlRbDescCommon { op_id },
            addr: 0,
            len: 0,
            key: mr.key,
            pd_hdl: 0,
            acc_flags: 0,
            pgt_offset: 0,
        });

        let res = self.do_ctrl_op(op_id, desc)?;

        if !res {
            return Err(Error::DeviceReturnFailed);
        }

        mr_pgt.dealloc(
            mr_ctx.pgt_offset,
            mr_ctx.len.div_ceil(mr_ctx.pg_size) as usize,
        );

        pd_ctx.mr.remove(&mr);
        mr_table[mr_idx as usize] = None;

        Ok(())
    }
}

impl MrPgt {
    pub(crate) fn new() -> Self {
        let free_blk = Box::into_raw(Box::new(MrPgtFreeBlk {
            idx: 0,
            len: crate::MR_PGT_SIZE,
            prev: ptr::null_mut(),
            next: ptr::null_mut(),
        }));

        Self {
            table: [0; crate::MR_PGT_SIZE],
            free_blk_list: free_blk,
        }
    }

    fn alloc(&mut self, len: usize) -> Result<usize, Error> {
        let mut ptr = self.free_blk_list;

        while !ptr.is_null() {
            let blk = unsafe { ptr.as_mut().unwrap_unchecked() };

            if blk.len >= len {
                let idx = blk.idx;

                blk.idx += len;
                blk.len -= len;

                if blk.len == 0 {
                    if !blk.prev.is_null() {
                        let prev = unsafe { blk.prev.as_mut().unwrap_unchecked() };
                        prev.next = blk.next;
                    } else {
                        self.free_blk_list = blk.next;
                    }

                    if !blk.next.is_null() {
                        let next = unsafe { blk.next.as_mut().unwrap_unchecked() };
                        next.prev = blk.prev;
                    }

                    drop(unsafe { Box::from_raw(ptr) });
                }

                return Ok(idx);
            }

            ptr = blk.next;
        }

        Err(Error::AllocPageTable)
    }

    fn dealloc(&mut self, idx: usize, len: usize) {
        let mut prev_ptr = ptr::null_mut();
        let mut ptr = self.free_blk_list;

        while !ptr.is_null() {
            let blk = unsafe { ptr.as_mut().unwrap_unchecked() };

            if blk.len > len {
                break;
            }

            prev_ptr = ptr;
            ptr = blk.next;
        }

        let new_ptr = Box::into_raw(Box::new(MrPgtFreeBlk {
            idx,
            len,
            prev: prev_ptr,
            next: ptr,
        }));

        let new = unsafe { new_ptr.as_mut().unwrap_unchecked() };

        if !new.prev.is_null() {
            let new_prev = unsafe { new.prev.as_mut().unwrap_unchecked() };
            new_prev.next = new_ptr;
        } else {
            self.free_blk_list = new_ptr;
        }

        if !new.next.is_null() {
            let new_next = unsafe { new.next.as_mut().unwrap_unchecked() };
            new_next.prev = new_ptr;
        }

        while !new.prev.is_null() {
            let new_prev = unsafe { new.prev.as_mut().unwrap_unchecked() };

            if new_prev.idx + new_prev.len != new.len {
                break;
            }

            new.idx = new_prev.idx;
            new.len += new_prev.len;

            let new_prev_prev_ptr = new_prev.prev;
            drop(unsafe { Box::from_raw(new.prev) });

            if !new_prev_prev_ptr.is_null() {
                let new_prev_prev = unsafe { new_prev_prev_ptr.as_mut().unwrap_unchecked() };
                new_prev_prev.next = new_ptr;
            } else {
                self.free_blk_list = new_ptr;
            }

            new.prev = new_prev_prev_ptr;
        }

        while !new.next.is_null() {
            let new_next = unsafe { new.next.as_mut().unwrap_unchecked() };

            if new_next.idx != new.idx + new.len {
                break;
            }

            new.len += new_next.len;

            let new_next_next_ptr = new_next.next;
            drop(unsafe { Box::from_raw(new.next) });

            if !new_next_next_ptr.is_null() {
                let new_next_next = unsafe { new_next_next_ptr.as_mut().unwrap_unchecked() };
                new_next_next.prev = new_ptr;
            }

            new.next = new_next_next_ptr;
        }
    }
}

unsafe impl Send for MrPgt {}
unsafe impl Sync for MrPgt {}

impl Hash for Mr {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.key.hash(state);
    }
}

impl PartialEq for Mr {
    fn eq(&self, other: &Self) -> bool {
        self.key == other.key
    }
}

impl Eq for Mr {}
