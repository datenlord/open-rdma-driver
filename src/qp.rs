use crate::{
    device::{
        Pmtu as DevicePmtu, QpType as DeviceQpType, ToCardCtrlRbDesc, ToCardCtrlRbDescCommon,
        ToCardCtrlRbDescQpManagement,
    },
    Device, Error, Pd,
};
use rand::RngCore as _;
use std::{
    hash::{Hash, Hasher},
    mem,
    net::Ipv4Addr,
    sync::atomic::{AtomicBool, Ordering},
};

const QP_MAX_CNT: usize = 1;
static QP_AVAILABLITY: [AtomicBool; QP_MAX_CNT] = unsafe { mem::transmute([true; QP_MAX_CNT]) };

#[allow(unused)]
#[derive(Debug, Clone)]
pub struct Qp {
    pub(crate) handle: u32,
    pub(crate) pd: Pd,
    pub(crate) qpn: u32,
    pub(crate) qp_type: DeviceQpType,
    pub(crate) rq_acc_flags: u8,
    pub(crate) pmtu: DevicePmtu,
    pub(crate) dqpn: u32,
    pub(crate) dqp_ip: Ipv4Addr,
    pub(crate) mac_addr: [u8; 6],
}

impl Qp {
    pub fn get_qpn(&self) -> u32 {
        self.qpn
    }
    pub fn get_dqpn(&self) -> u32 {
        self.dqpn
    }
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

pub enum Pmtu {
    Mtu256 = 1,
    Mtu512 = 2,
    Mtu1024 = 3,
    Mtu2048 = 4,
    Mtu4096 = 5,
}

impl Device {
    #[allow(clippy::too_many_arguments)]
    pub fn create_qp(
        &self,
        pd: Pd,
        qp_type: QpType,
        pmtu: Pmtu,
        rq_acc_flags: u8,
        dqpn: u32,
        dqp_ip: Ipv4Addr,
        mac_addr: [u8; 6],
    ) -> Result<Qp, Error> {
        let mut qp_pool = self.0.qp.lock().unwrap();
        let mut pd_pool = self.0.pd.lock().unwrap();

        // TODO: by IB spec, QP0 and QP1 are reserved, so qpn should start with 2
        let Some(qpn) = QP_AVAILABLITY
            .iter()
            .enumerate()
            .find_map(|(idx, n)| n.swap(false, Ordering::AcqRel).then_some(idx))
        else {
            return Err(Error::NoAvailableQp);
        };

        let qp = Qp {
            handle: rand::thread_rng().next_u32(), // TODO: don't use random number as handler,and why not use QPN as handle?
            pd,
            qpn: qpn as u32,
            qp_type: DeviceQpType::from(qp_type),
            rq_acc_flags,
            pmtu: DevicePmtu::from(pmtu),
            dqpn,
            dqp_ip,
            mac_addr,
        };

        let pd_ctx = pd_pool.get_mut(&qp.pd).ok_or(Error::InvalidPd)?;

        let op_id = super::get_ctrl_op_id();

        let desc = ToCardCtrlRbDesc::QpManagement(ToCardCtrlRbDescQpManagement {
            common: ToCardCtrlRbDescCommon { op_id },
            is_valid: true,
            qpn: qp.qpn,
            pd_hdl: qp.pd.handle,
            qp_type: qp.qp_type.clone(),
            rq_acc_flags,
            pmtu: qp.pmtu.clone(),
        });

        let res = self.do_ctrl_op(op_id, desc)?;

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

        let op_id = super::get_ctrl_op_id();

        let desc = ToCardCtrlRbDesc::QpManagement(ToCardCtrlRbDescQpManagement {
            common: ToCardCtrlRbDescCommon { op_id },
            is_valid: false,
            qpn: qp.qpn,
            pd_hdl: 0,
            qp_type: qp.qp_type.clone(),
            rq_acc_flags: 0,
            pmtu: qp.pmtu.clone(),
        });

        let res = self.do_ctrl_op(op_id, desc)?;

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

impl From<Pmtu> for DevicePmtu {
    fn from(pmtu: Pmtu) -> Self {
        match pmtu {
            Pmtu::Mtu256 => Self::Mtu256,
            Pmtu::Mtu512 => Self::Mtu512,
            Pmtu::Mtu1024 => Self::Mtu1024,
            Pmtu::Mtu2048 => Self::Mtu2048,
            Pmtu::Mtu4096 => Self::Mtu4096,
        }
    }
}
