use crate::{
    device::{
        ToHostWorkRbDesc, ToHostWorkRbDescAck, ToHostWorkRbDescNack, ToHostWorkRbDescRead,
        ToHostWorkRbDescStatus, ToHostWorkRbDescWrite, ToHostWorkRbDescWriteType,
        ToHostWorkRbDescWriteWithImm,
    },
    Device, RecvPktMap,
};

impl Device {
    pub(crate) fn poll_work_rb(self) {
        loop {
            let desc = self.0.adaptor.to_host_work_rb().pop();

            match desc {
                ToHostWorkRbDesc::Read(desc) => self.handle_work_desc_read(desc),
                ToHostWorkRbDesc::Write(desc) => self.handle_work_desc_write(desc),
                ToHostWorkRbDesc::WriteWithImm(desc) => self.handle_work_desc_write_with_imm(desc),
                ToHostWorkRbDesc::Ack(desc) => self.handle_work_desc_ack(desc),
                ToHostWorkRbDesc::Nack(desc) => self.handle_work_desc_nack(desc),
            }
        }
    }

    fn handle_work_desc_read(&self, _desc: ToHostWorkRbDescRead) {
        todo!()
    }

    fn handle_work_desc_write(&self, desc: ToHostWorkRbDescWrite) {
        match desc.common.status {
            ToHostWorkRbDescStatus::Normal => {
                let pkt_map = unsafe {
                    (&self.0.revc_pkt_map as *const _ as *mut RecvPktMap)
                        .as_mut()
                        .unwrap_unchecked()
                };

                // new pkt_map
                if matches!(
                    desc.write_type,
                    ToHostWorkRbDescWriteType::First | ToHostWorkRbDescWriteType::Only
                ) {
                    let qp_table = self.0.qp.lock().unwrap();
                    let (qp, qp_ctx) = qp_table.iter().next().unwrap();

                    let real_payload_len = desc.len - desc.common.pad_cnt as u32;

                    let first_pkt_len =
                        if matches!(desc.write_type, ToHostWorkRbDescWriteType::First) {
                            u64::from(&qp.pmtu) - (desc.addr & (u64::from(&qp.pmtu) - 1))
                        } else {
                            real_payload_len as u64
                        };

                    let pkt_cnt = 1
                        + (real_payload_len - first_pkt_len as u32)
                            .div_ceil(u64::from(&qp.pmtu) as u32);

                    *pkt_map = RecvPktMap::new(pkt_cnt as usize, qp_ctx.recv_psn);

                    // unblock recv_pkt_comp_thread
                    self.0.check_recv_pkt_comp_thread.get().unwrap().unpark();
                }

                pkt_map.insert(desc.psn);
            }
            _ => todo!(),
        }
    }

    fn handle_work_desc_write_with_imm(&self, _desc: ToHostWorkRbDescWriteWithImm) {
        todo!()
    }

    fn handle_work_desc_ack(&self, _desc: ToHostWorkRbDescAck) {
        let mut ctx_map = self.0.send_op_ctx.lock().unwrap();

        let Some((_, ctx)) = ctx_map.iter_mut().next() else {
            eprintln!("no send ctx found");
            return;
        };

        ctx.result = Some(true);
        ctx.thread.unpark();
    }

    fn handle_work_desc_nack(&self, _desc: ToHostWorkRbDescNack) {
        todo!()
    }
}
