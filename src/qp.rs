use crate::{
    device::{ToCardCtrlRbDesc, ToCardCtrlRbDescCommon, ToCardCtrlRbDescQpManagement},
    types::{MemAccessTypeFlag, Pmtu, QpType, Qpn, Psn},
    Device, Error, Pd,
};
use std::{
    hash::{Hash, Hasher},
    net::Ipv4Addr,
    sync::{
        atomic::Ordering,
        Mutex,
    },
};

// // FIXME: don't use static here. It should belong to device
// static QP_AVAILABLITY: [AtomicBool; QP_MAX_CNT] = unsafe { mem::transmute([true; QP_MAX_CNT]) };

#[derive(Debug, Clone)]
pub struct Qp {
    pub(crate) handle: u32,
    pub(crate) _pd: Pd,
    pub(crate) qpn: Qpn,
    pub(crate) _qp_type: QpType,
    pub(crate) _rq_acc_flags: MemAccessTypeFlag,
    pub(crate) _pmtu: Pmtu,
    pub(crate) _dqp_ip: Ipv4Addr,
    pub(crate) _mac_addr: [u8; 6],
}

pub struct QpContext {
    pub(crate) handle: u32,
    pub(crate) pd: Pd,
    pub(crate) qpn: Qpn,
    pub(crate) qp_type: QpType,
    pub(crate) rq_acc_flags: MemAccessTypeFlag,
    pub(crate) pmtu: Pmtu,
    pub(crate) dqp_ip: Ipv4Addr,
    pub(crate) mac_addr: [u8; 6],
    pub(crate) inner: Mutex<QpInner>,
}

impl Qp {
    pub fn get_qpn(&self) -> Qpn {
        self.qpn
    }
}

pub(crate) struct QpInner {
    pub(crate) send_psn: Psn,
    #[allow(dead_code)]
    pub(crate) recv_psn: Psn,
}

impl Device {
    #[allow(clippy::too_many_arguments)]
    pub fn create_qp(
        &self,
        pd: Pd,
        qp_type: QpType,
        pmtu: Pmtu,
        rq_acc_flags: MemAccessTypeFlag,
        dqp_ip: Ipv4Addr,
        mac_addr: [u8; 6],
    ) -> Result<Qp, Error> {
        let mut qp_pool = self.0.qp_table.write().unwrap();
        let mut pd_pool = self.0.pd.lock().unwrap();

        // TODO: 
        let Some(qpn) = self.0.qp_availability
            .iter()
            .enumerate()
            .find_map(|(idx, n)| n.swap(false, Ordering::AcqRel).then_some(idx))
        else {
            return Err(Error::NoAvailableQp);
        };
        let qpn = Qpn::new(qpn as u32);
        let qp = QpContext {
            handle: qpn.get(),
            pd: pd.clone(),
            qpn,
            qp_type,
            rq_acc_flags,
            pmtu: pmtu.clone(),
            dqp_ip,
            mac_addr,
            inner: Mutex::new(QpInner {
                send_psn: Psn::new(0),
                recv_psn: Psn::new(0),
            }),
        };

        let pd_ctx = pd_pool.get_mut(&pd).ok_or(Error::InvalidPd)?;

        let op_id = self.get_ctrl_op_id();

        let desc = ToCardCtrlRbDesc::QpManagement(ToCardCtrlRbDescQpManagement {
            common: ToCardCtrlRbDescCommon { op_id },
            is_valid: true,
            qpn: qp.qpn,
            pd_hdl: qp.pd.handle,
            qp_type: qp.qp_type,
            rq_acc_flags: qp.rq_acc_flags,
            pmtu: qp.pmtu.clone(),
        });

        let res = self.do_ctrl_op(op_id, desc)?;

        if !res {
            return Err(Error::DeviceReturnFailed);
        }
        let ret_qp = Qp {
            handle: qp.handle,
            _pd: pd,
            qpn,
            _qp_type: qp.qp_type,
            _rq_acc_flags: rq_acc_flags,
            _pmtu: pmtu,
            _dqp_ip: dqp_ip,
            _mac_addr: mac_addr,
        };
        let pd_res = pd_ctx.qp.insert(qpn);
        let qp_res = qp_pool.insert(qpn, qp);

        assert!(pd_res);
        assert!(qp_res.is_none());

        Ok(ret_qp)
    }

    pub fn destroy_qp(&self, qp: Qpn) -> Result<(), Error> {
        let mut qp_pool = self.0.qp_table.write().unwrap();
        let mut pd_pool = self.0.pd.lock().unwrap();

        let op_id = self.get_ctrl_op_id();

        let (pd_ctx, desc) = if let Some(qp_ctx) = qp_pool.get(&qp) {
            let pd_ctx = pd_pool.get_mut(&qp_ctx.pd).ok_or(Error::InvalidPd)?;
            let desc = ToCardCtrlRbDesc::QpManagement(ToCardCtrlRbDescQpManagement {
                common: ToCardCtrlRbDescCommon { op_id },
                is_valid: false,
                qpn: qp_ctx.qpn,
                pd_hdl: 0,
                qp_type: qp_ctx.qp_type,
                rq_acc_flags: MemAccessTypeFlag::IbvAccessNoFlags,
                pmtu: qp_ctx.pmtu.clone(),
            });
            (pd_ctx, desc)
        } else {
            return Err(Error::InvalidQp);
        };

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
