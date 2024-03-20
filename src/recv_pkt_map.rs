use std::mem;

use crate::types::{Psn, Qpn};

pub(crate) struct RecvPktMap {
    start_psn: Psn,
    end_psn: Psn,
    stage_0: Box<[u64]>,
    stage_0_last_chunk: u64,
    stage_1: Box<[u64]>,
    stage_1_last_chunk: u64,
    stage_2: Box<[u64]>,
    stage_2_last_chunk: u64,
    last_pkt_psn: Psn,
    is_out_of_order: bool,
    dqpn: Qpn,
}

impl RecvPktMap {
    const FULL_CHUNK_DIV_BIT_SHIFT_CNT: u32 = 64usize.ilog2();
    const LAST_CHUNK_MOD_MASK: usize = mem::size_of::<u64>() * 8 - 1;

    pub(crate) fn new(pkt_cnt: usize, start_psn: Psn, dqpn: Qpn) -> Self {
        let create_stage = |len| {
            // used-bit count in the last u64, len % 64
            let rem = len & Self::LAST_CHUNK_MOD_MASK;
            // number of u64, ceil(len / 64)
            let len = (len >> Self::FULL_CHUNK_DIV_BIT_SHIFT_CNT) + (rem != 0) as usize;
            // last u64, lower `rem` bits are 1, higher bits are 0. if `rem == 0``, all bits are 1
            let last_chunk = ((1u64 << rem) - 1) | ((rem != 0) as u64).wrapping_sub(1);

            (vec![0; len].into_boxed_slice(), last_chunk)
        };

        let (stage_0, stage_0_last_chunk) = create_stage(pkt_cnt);
        let (stage_1, stage_1_last_chunk) = create_stage(stage_0.len());
        let (stage_2, stage_2_last_chunk) = create_stage(stage_1.len());

        Self {
            start_psn,
            end_psn: start_psn.wrapping_add(pkt_cnt as u32 - 1),
            stage_0,
            stage_0_last_chunk,
            stage_1,
            stage_1_last_chunk,
            stage_2,
            stage_2_last_chunk,
            last_pkt_psn: start_psn.wrapping_sub(1),
            is_out_of_order: false,
            dqpn,
        }
    }

    pub(crate) fn insert(&mut self, new_psn: Psn) {
        let psn = (new_psn.wrapping_abs(self.start_psn)) as usize;
        let stage_0_idx = psn >> Self::FULL_CHUNK_DIV_BIT_SHIFT_CNT; // which u64 in stage 0
        let stage_0_rem = psn & Self::LAST_CHUNK_MOD_MASK; // bit position in u64
        let stage_0_bit = 1 << stage_0_rem; // bit mask
        self.stage_0[stage_0_idx] |= stage_0_bit; // set bit in stage 0

        let is_stage_0_last_chunk = stage_0_idx == self.stage_0.len() - 1; // is the bit in the last u64 in stage 0
        let stage_0_chunk_expected =
            (is_stage_0_last_chunk as u64).wrapping_sub(1) | self.stage_0_last_chunk; // expected bit mask of the target u64 in stage 0
        let is_stage_0_chunk_complete = self.stage_0[stage_0_idx] == stage_0_chunk_expected; // is the target u64 in stage 0 full

        let stage_1_idx = stage_0_idx >> Self::FULL_CHUNK_DIV_BIT_SHIFT_CNT; // which u64 in stage 1
        let stage_1_rem = stage_0_idx & Self::LAST_CHUNK_MOD_MASK; // bit position in u64
        let stage_1_bit = (is_stage_0_chunk_complete as u64) << stage_1_rem; // bit mask
        self.stage_1[stage_1_idx] |= stage_1_bit; // set bit in stage 1

        let is_stage_1_last_chunk = stage_1_idx == self.stage_1.len() - 1; // is the bit in the last u64 in stage 1
        let stage_1_chunk_expected =
            (is_stage_1_last_chunk as u64).wrapping_sub(1) | self.stage_1_last_chunk; // expected bit mask of the target u64 in stage 1
        let is_stage_1_chunk_complete = self.stage_1[stage_1_idx] == stage_1_chunk_expected; // is the target u64 in stage 1 full

        let stage_2_idx = stage_1_idx >> Self::FULL_CHUNK_DIV_BIT_SHIFT_CNT; // which u64 in stage 2
        let stage_2_rem = stage_1_idx & Self::LAST_CHUNK_MOD_MASK; // bit position in u64
        let stage_2_bit = (is_stage_1_chunk_complete as u64) << stage_2_rem; // bit mask
        self.stage_2[stage_2_idx] |= stage_2_bit; // set bit in stage 2
        if self.last_pkt_psn.wrapping_add(1) != new_psn {
            self.is_out_of_order = true;
        }
        self.last_pkt_psn = new_psn;
    }

    pub(crate) fn is_out_of_order(&self) -> bool {
        self.is_out_of_order
    }

    pub(crate) fn is_complete(&self) -> bool {
        self.stage_2
            .iter()
            .enumerate()
            .fold(true, |acc, (idx, &bits)| {
                let is_last_chunk = idx == self.stage_2.len() - 1;
                let chunk_expected =
                    (is_last_chunk as u64).wrapping_sub(1) | self.stage_2_last_chunk;
                let is_chunk_complete = bits == chunk_expected;
                acc && is_chunk_complete
            })
    }

    pub(crate) fn dqpn(&self) -> Qpn {
        self.dqpn
    }

    pub(crate) fn end_psn(&self) -> Psn {
        self.end_psn
    }
}
