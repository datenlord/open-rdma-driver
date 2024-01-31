use crate::Device;

impl Device {
    pub(super) fn poll_ctrl_rb(self) {
        loop {
            let _desc = self.0.adaptor.to_host_ctrl_rb().pop();

            todo!()
        }
    }

    pub(super) fn poll_work_rb(self) {
        loop {
            let _desc = self.0.adaptor.to_host_work_rb().pop();

            todo!()
        }
    }
}
