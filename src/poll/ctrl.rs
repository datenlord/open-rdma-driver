use crate::{
    device::{
        CtrlRbDescCommonHeader, ToHostCtrlRbDesc, ToHostCtrlRbDescQpManagement,
        ToHostCtrlRbDescUpdateMrTable, ToHostCtrlRbDescUpdatePageTable,
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
        let ToHostCtrlRbDescUpdateMrTable {
            common_header:
                CtrlRbDescCommonHeader {
                    user_data: id,
                    is_success_or_need_signal_cplt: is_success,
                    ..
                },
        } = desc;

        let mut ctx_map = self.0.ctrl_op_ctx.lock().unwrap();

        let Some(ctx) = ctx_map.get_mut(&id) else {
            eprintln!("no ctrl cmd ctx found");
            return;
        };

        ctx.result = Some(is_success);
        ctx.thread.unpark();
    }

    fn handle_ctrl_desc_update_page_table(&self, desc: ToHostCtrlRbDescUpdatePageTable) {
        let ToHostCtrlRbDescUpdatePageTable {
            common_header:
                CtrlRbDescCommonHeader {
                    user_data: id,
                    is_success_or_need_signal_cplt: is_success,
                    ..
                },
        } = desc;

        let mut ctx_map = self.0.ctrl_op_ctx.lock().unwrap();

        let Some(ctx) = ctx_map.get_mut(&id) else {
            eprintln!("no ctrl cmd ctx found");
            return;
        };

        ctx.result = Some(is_success);
        ctx.thread.unpark();
    }

    fn handle_ctrl_desc_qp_management(&self, desc: ToHostCtrlRbDescQpManagement) {
        let ToHostCtrlRbDescQpManagement {
            common_header:
                CtrlRbDescCommonHeader {
                    user_data: id,
                    is_success_or_need_signal_cplt: is_success,
                    ..
                },
        } = desc;

        let mut ctx_map = self.0.ctrl_op_ctx.lock().unwrap();

        let Some(ctx) = ctx_map.get_mut(&id) else {
            eprintln!("no ctrl cmd ctx found");
            return;
        };

        ctx.result = Some(is_success);
        ctx.thread.unpark();
    }
}
