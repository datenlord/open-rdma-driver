use crate::{
    device::{
        ToHostCtrlRbDesc, ToHostCtrlRbDescQpManagement, ToHostCtrlRbDescUpdateMrTable,
        ToHostCtrlRbDescUpdatePageTable,
    },
    Device,
};

impl Device {
    pub(crate) fn poll_ctrl_rb(self) {
        loop {
            let desc = self.0.adaptor.to_host_ctrl_rb().pop();
            match desc {
                ToHostCtrlRbDesc::UpdateMrTable(desc) => {
                    self.handle_ctrl_desc_update_mr_table(desc)
                }
                ToHostCtrlRbDesc::UpdatePageTable(desc) => {
                    self.handle_ctrl_desc_update_page_table(desc)
                }
                ToHostCtrlRbDesc::QpManagement(desc) => self.handle_ctrl_desc_qp_management(desc),
            }
        }
    }

    fn handle_ctrl_desc_update_mr_table(&self, desc: ToHostCtrlRbDescUpdateMrTable) {
        let ctx_map = self.0.ctrl_op_ctx_map.read().unwrap();

        if let Some(ctx) = ctx_map.get(&desc.common.op_id) {
            ctx.set_result(desc.common.is_success);
        } else {
            eprintln!("no ctrl cmd ctx found");
        }
    }

    fn handle_ctrl_desc_update_page_table(&self, desc: ToHostCtrlRbDescUpdatePageTable) {
        let ctx_map = self.0.ctrl_op_ctx_map.read().unwrap();

        if let Some(ctx) = ctx_map.get(&desc.common.op_id) {
            ctx.set_result(desc.common.is_success);
        } else {
            eprintln!("no ctrl cmd ctx found");
        }
    }

    fn handle_ctrl_desc_qp_management(&self, desc: ToHostCtrlRbDescQpManagement) {
        let ctx_map = self.0.ctrl_op_ctx_map.read().unwrap();

        if let Some(ctx) = ctx_map.get(&desc.common.op_id) {
            ctx.set_result(desc.common.is_success);
        } else {
            eprintln!("no ctrl cmd ctx found");
        }
    }
}
