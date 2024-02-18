use crate::{
    device::{
        CtrlRbDescCommonHeader, CtrlRbDescOpcode, Pmtu as DevicePmtu, QpType as DeviceQpType,
        ToCardCtrlRbDesc, ToCardCtrlRbDescQpManagement,
    },
    Device, Error, Pd,
};
use rand::RngCore as _;
use std::{
    hash::{Hash, Hasher},
    sync::atomic::{AtomicBool, Ordering},
};

const MAX_QP_CNT: usize = 1;
static QP_AVAILABLE: [AtomicBool; MAX_QP_CNT] = [AtomicBool::new(true); MAX_QP_CNT];

#[derive(Debug, Clone)]
pub struct Qp {
    pub(crate) handle: u32,
    pub(crate) pd: Pd,
    pub(crate) qpn: u32,
    pub(crate) qp_type: DeviceQpType,
    pub(crate) rq_acc_flags: u8,
    pub(crate) pmtu: DevicePmtu,
}

pub(crate) struct QpCtx {
    pub(crate) send_psn: u32,
    pub(crate) recv_psn: u32,
}

pub enum QpType {
    Rc = 2,
    Uc = 3,
    Ud = 4,
}

impl Device {
    pub fn create_qp(&self, pd: Pd, qp_type: QpType, rq_acc_flags: u8) -> Result<Qp, Error> {
        let mut qp_pool = self.0.qp.lock().unwrap();
        let mut pd_pool = self.0.pd.lock().unwrap();

        let Some(qpn) = QP_AVAILABLE
            .iter()
            .enumerate()
            .find_map(|(idx, n)| n.swap(false, Ordering::AcqRel).then_some(idx))
        else {
            return Err(Error::NoAvailableQp);
        };

        let qp = Qp {
            handle: rand::thread_rng().next_u32(),
            pd,
            qpn: qpn as u32,
            qp_type: DeviceQpType::from(qp_type),
            rq_acc_flags,
            pmtu: DevicePmtu::Mtu4096, // TODO: retrieve PMTU?
        };

        let pd_ctx = pd_pool.get_mut(&qp.pd).ok_or(Error::InvalidPd)?;

        let id = super::get_ctrl_op_id();

        let desc_header = CtrlRbDescCommonHeader {
            valid: true,
            opcode: CtrlRbDescOpcode::QpManagement,
            extra_segment_cnt: 0,
            is_success_or_need_signal_cplt: false,
            user_data: id,
        };

        let desc = ToCardCtrlRbDesc::QpManagement(ToCardCtrlRbDescQpManagement {
            common_header: desc_header,
            is_valid: true,
            is_error: false,
            qpn: qp.qpn,
            pd_handler: qp.pd.handle,
            qp_type: qp.qp_type.clone(),
            rq_access_flags: qp.rq_acc_flags,
            pmtu: qp.pmtu.clone(),
        });

        let res = self.do_ctrl_op(id, desc)?;

        if !res {
            return Err(Error::DeviceReturnFailed);
        }

        let pd_res = pd_ctx.qp.insert(qp.clone());
        let qp_res = qp_pool.insert(
            qp.clone(),
            QpCtx {
                send_psn: 0,
                recv_psn: 0,
            },
        );

        assert!(pd_res);
        assert!(qp_res.is_none());

        Ok(qp)
    }

    pub fn destroy_qp(&self, qp: Qp) -> Result<(), Error> {
        let mut qp_pool = self.0.qp.lock().unwrap();
        let mut pd_pool = self.0.pd.lock().unwrap();

        if !qp_pool.contains_key(&qp) {
            return Err(Error::InvalidQp);
        }

        let pd_ctx = pd_pool.get_mut(&qp.pd).ok_or(Error::InvalidPd)?;

        let id = super::get_ctrl_op_id();

        let desc_header = CtrlRbDescCommonHeader {
            valid: false,
            opcode: CtrlRbDescOpcode::QpManagement,
            extra_segment_cnt: 0,
            is_success_or_need_signal_cplt: false,
            user_data: id,
        };

        let desc = ToCardCtrlRbDesc::QpManagement(ToCardCtrlRbDescQpManagement {
            common_header: desc_header,
            is_valid: true,
            is_error: false,
            qpn: qp.qpn,
            pd_handler: qp.pd.handle,
            qp_type: qp.qp_type.clone(),
            rq_access_flags: qp.rq_acc_flags,
            pmtu: qp.pmtu.clone(),
        });

        let res = self.do_ctrl_op(id, desc)?;

        if !res {
            return Err(Error::DeviceReturnFailed);
        }

        pd_ctx.qp.remove(&qp);
        qp_pool.remove(&qp);

        Ok(())
    }
}

impl Hash for Qp {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.handle.hash(state);
    }
}

impl PartialEq for Qp {
    fn eq(&self, other: &Self) -> bool {
        self.handle == other.handle
    }
}

impl Eq for Qp {}

impl From<QpType> for DeviceQpType {
    fn from(ty: QpType) -> Self {
        match ty {
            QpType::Rc => Self::Rc,
            QpType::Uc => Self::Uc,
            QpType::Ud => Self::Ud,
        }
    }
}
