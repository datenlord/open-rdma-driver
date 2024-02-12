use crate::{
    device::{
        RdmaReqStatus, ToHostWorkRbDesc, ToHostWorkRbDescBth, ToHostWorkRbDescFragBth,
        ToHostWorkRbDescSendQueueReport, ToHostWorkRbDescType,
    },
    Device, RecvPktMap,
};

impl Device {
    pub(crate) fn poll_work_rb(self) {
        loop {
            let desc = self.0.adaptor.to_host_work_rb().pop();

            match desc {
                ToHostWorkRbDesc::SendQueueReport(desc) => self.handle_work_desc_send_report(desc),
                ToHostWorkRbDesc::Bth(desc) => self.handle_work_desc_bth(desc),
                ToHostWorkRbDesc::BthAeth(_desc) => todo!(),
                ToHostWorkRbDesc::BthRethImmDt(_desc) => todo!(),
                ToHostWorkRbDesc::SecondaryReth(_desc) => todo!(),
            }
        }
    }

    fn handle_work_desc_send_report(&self, _desc: ToHostWorkRbDescSendQueueReport) {
        let mut ctx_map = self.0.recv_op_ctx.lock().unwrap();

        let Some((_, ctx)) = ctx_map.iter_mut().next() else {
            eprintln!("no send ctx found");
            return;
        };

        ctx.result = Some(true);
    }

    fn handle_work_desc_bth(&self, desc: ToHostWorkRbDescBth) {
        assert_eq!(desc.desc_type, ToHostWorkRbDescType::RecvPacketMeta);

        match desc.req_status {
            RdmaReqStatus::Normal => self.handle_work_desc_bth_normal(desc.bth),
            status => self.handle_work_desc_bth_error(status, desc.bth),
        }
    }

    fn handle_work_desc_bth_normal(&self, bth: ToHostWorkRbDescFragBth) {
        let pkt_map = unsafe {
            (&self.0.revc_pkt_map as *const _ as *mut RecvPktMap)
                .as_mut()
                .unwrap_unchecked()
        };

        pkt_map.insert(bth.psn);
    }

    fn handle_work_desc_bth_error(&self, _status: RdmaReqStatus, _bth: ToHostWorkRbDescFragBth) {
        todo!()
    }
}
