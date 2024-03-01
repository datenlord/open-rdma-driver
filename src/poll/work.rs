use crate::{
    device::{
        ToHostWorkRbDesc, ToHostWorkRbDescAck, ToHostWorkRbDescNack, ToHostWorkRbDescRead,
        ToHostWorkRbDescStatus, ToHostWorkRbDescWrite, ToHostWorkRbDescWriteWithImm,
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
