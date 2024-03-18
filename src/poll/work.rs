use core::panic;
use std::{
    collections::HashMap,
    sync::{Arc, Mutex, RwLock},
};

use crate::{
    device::{
        ToHostRb, ToHostWorkRbDesc, ToHostWorkRbDescAck, ToHostWorkRbDescNack,
        ToHostWorkRbDescRead, ToHostWorkRbDescStatus, ToHostWorkRbDescWrite,
        ToHostWorkRbDescWriteType, ToHostWorkRbDescWriteWithImm,
    },
    qp::QpContext,
    responser::{RespCommand, RespReadRespCommand},
    types::{Key, Qpn, Psn},
    RecvPktMap, op_ctx::WriteOpCtx,
};

// TODO: currently we don't have MSN, so we use qpn+psn as index.


#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub(crate) struct QpnWithLastPsn {
    qpn : Qpn,
    psn : Psn,
}

impl QpnWithLastPsn {
    pub fn new(qpn: Qpn, psn: Psn) -> Self {
        Self { qpn,psn }
    }
}

// TODO: currently we don't have MSN, so we use qpn+rkey as index.
#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub(crate) struct RKeyWithQpn {
    key: Key,
    qpn: Qpn,
}

impl RKeyWithQpn {
    pub fn new(key: Key, qpn: Qpn) -> Self {
        Self { key, qpn }
    }
}

pub struct WorkDescPoller {
    _thread: std::thread::JoinHandle<()>,
}

pub(crate) struct WorkDescPollerContext {
    work_rb: Arc<dyn ToHostRb<ToHostWorkRbDesc>>,
    recv_pkt_map: Arc<RwLock<HashMap<RKeyWithQpn, Mutex<RecvPktMap>>>>,
    qp_table: Arc<RwLock<HashMap<Qpn, QpContext>>>,
    sending_queue: std::sync::mpsc::Sender<RespCommand>,
    write_op_ctx_map : Arc<RwLock<HashMap<QpnWithLastPsn,WriteOpCtx>>>
}

unsafe impl Send for WorkDescPollerContext {}

enum ThreadFlag {
    Running,
    Stopped(&'static str),
}

impl WorkDescPoller {
    pub(crate) fn new(
        work_rb: Arc<dyn ToHostRb<ToHostWorkRbDesc>>,
        recv_pkt_map: Arc<RwLock<HashMap<RKeyWithQpn, Mutex<RecvPktMap>>>>,
        qp_table: Arc<RwLock<HashMap<Qpn, QpContext>>>,
        sending_queue: std::sync::mpsc::Sender<RespCommand>,
        write_op_ctx_map : Arc<RwLock<HashMap<QpnWithLastPsn,WriteOpCtx>>>
    ) -> Self {
        let ctx = WorkDescPollerContext {
            work_rb,
            recv_pkt_map,
            qp_table,
            sending_queue,
            write_op_ctx_map
        };
        let thread = std::thread::spawn(move || WorkDescPollerContext::poll_working_thread(ctx));

        Self { _thread: thread }
    }
}

impl WorkDescPollerContext {
    pub(crate) fn poll_working_thread(ctx: Self) {
        loop {
            let desc = ctx.work_rb.pop();

            if !matches!(desc.common().status, ToHostWorkRbDescStatus::Normal) {
                eprintln!("desc status is {:?}", desc.common().status);
                continue;
            }

            let flag = match desc {
                ToHostWorkRbDesc::Read(desc) => ctx.handle_work_desc_read(desc),
                ToHostWorkRbDesc::Write(desc) => ctx.handle_work_desc_write(desc),
                ToHostWorkRbDesc::WriteWithImm(desc) => ctx.handle_work_desc_write_with_imm(desc),
                ToHostWorkRbDesc::Ack(desc) => ctx.handle_work_desc_ack(desc),
                ToHostWorkRbDesc::Nack(desc) => ctx.handle_work_desc_nack(desc),
            };
            match flag {
                ThreadFlag::Stopped(reason) => {
                    eprintln!("poll_work_rb stopped: {}", reason);
                    return;
                }
                ThreadFlag::Running => {}
            }
        }
    }

    fn handle_work_desc_read(&self, desc: ToHostWorkRbDescRead) -> ThreadFlag {
        let command = RespCommand::ReadResponse(RespReadRespCommand { desc });
        if self.sending_queue.send(command).is_err() {
            ThreadFlag::Stopped("receive queue closed")
        } else {
            ThreadFlag::Running
        }
    }

    fn handle_work_desc_write(&self, desc: ToHostWorkRbDescWrite) -> ThreadFlag {
        // TODO: since we don't have the MSN currently, we use qpn+key as index.
        // But it's just a temporary solution.
        let fake_msn = RKeyWithQpn::new(desc.key, desc.common.dqpn);

        if matches!(
            desc.write_type,
            ToHostWorkRbDescWriteType::First | ToHostWorkRbDescWriteType::Only
        ) {
            let mut recv_pkt_map_guard = self.recv_pkt_map.write().unwrap();
            let real_payload_len = desc.len - desc.common.pad_cnt as u32;
            let guard = self.qp_table.read().unwrap();

            let pmtu = if let Some(qp_ctx) = guard.get(&desc.common.dqpn) {
                qp_ctx.pmtu.clone()
            } else {
                eprintln!("{:?} not found", desc.common.dqpn.get());
                return ThreadFlag::Running;
            };
            drop(guard);

            let pmtu = u32::from(&pmtu);

            let first_pkt_len = if matches!(desc.write_type, ToHostWorkRbDescWriteType::First) {
                pmtu as u64 - (desc.addr & (pmtu as u64 - 1))
            } else {
                real_payload_len as u64
            };

            let pkt_cnt = 1 + (real_payload_len - first_pkt_len as u32).div_ceil(pmtu);
            recv_pkt_map_guard.insert(
                fake_msn.clone(),
                Mutex::new(RecvPktMap::new(
                    pkt_cnt as usize,
                    desc.psn,
                    desc.common.dqpn,
                )),
            );
        }

        let guard = self.recv_pkt_map.read().unwrap();
        if let Some(recv_pkt_map) = guard.get(&fake_msn) {
            let mut recv_pkt_map = recv_pkt_map.lock().unwrap();
            recv_pkt_map.insert(desc.psn);
        } else {
            eprintln!("recv_pkt_map not found for {:?}", fake_msn);
        }
        ThreadFlag::Running
    }

    fn handle_work_desc_write_with_imm(&self, _desc: ToHostWorkRbDescWriteWithImm) -> ThreadFlag {
        todo!()
    }

    fn handle_work_desc_ack(&self, desc: ToHostWorkRbDescAck) -> ThreadFlag {
        eprintln!("in handle_work_desc_ack");
        let guard = self.write_op_ctx_map.read().unwrap();
        let key = QpnWithLastPsn::new(desc.common.dqpn, desc.psn);
        if let Some(op_ctx) = guard.get(&key) {
            op_ctx.set_result(());
        } else {
            eprintln!("receive ack, but op_ctx not found for {:?}", key);
        }

        // TODO: since we don't have MSN yet, we don't have enough information to clear
        ThreadFlag::Running
    }

    fn handle_work_desc_nack(&self, _desc: ToHostWorkRbDescNack) -> ThreadFlag {
        panic!("receive a nack");
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::HashMap,
        net::Ipv4Addr,
        sync::{Arc, Mutex, RwLock},
        thread::sleep,
    };

    use crate::{
        device::{
            ToHostRb, ToHostWorkRbDesc, ToHostWorkRbDescCommon, ToHostWorkRbDescRead,
            ToHostWorkRbDescStatus, ToHostWorkRbDescTransType, ToHostWorkRbDescWrite,
            ToHostWorkRbDescWriteType, ToHostWorkRbDescAck,
        },
        qp::QpContext,
        responser::RespCommand,
        types::{Key, MemAccessTypeFlag, Psn, Qpn, Msn},
        Pd, op_ctx::WriteOpCtx,
    };

    use super::{WorkDescPoller, QpnWithLastPsn};

    struct MockToHostRb {
        rb: Mutex<Vec<ToHostWorkRbDesc>>,
    }
    impl MockToHostRb {
        fn new(v: Vec<ToHostWorkRbDesc>) -> Self {
            MockToHostRb { rb: Mutex::new(v) }
        }
    }
    impl ToHostRb<ToHostWorkRbDesc> for MockToHostRb {
        fn pop(&self) -> ToHostWorkRbDesc {
            let is_empty = self.rb.lock().unwrap().is_empty();
            if is_empty {
                sleep(std::time::Duration::from_secs(10))
            }
            self.rb.lock().unwrap().pop().unwrap()
        }
    }
    #[test]
    fn test_work_desc_poller() {
        let mut input = vec![
            // test writeFirst
            ToHostWorkRbDesc::Write(ToHostWorkRbDescWrite {
                common: ToHostWorkRbDescCommon {
                    dqpn: Qpn::new(3),
                    status: ToHostWorkRbDescStatus::Normal,
                    trans: ToHostWorkRbDescTransType::Rc,
                    pad_cnt: 0,
                },
                addr: 0,
                len: 3192,
                key: Key::new(0),
                write_type: ToHostWorkRbDescWriteType::First,
                psn: Psn::new(0),
            }),
            // test writeMiddle
            ToHostWorkRbDesc::Write(ToHostWorkRbDescWrite {
                common: ToHostWorkRbDescCommon {
                    dqpn: Qpn::new(3),
                    status: ToHostWorkRbDescStatus::Normal,
                    trans: ToHostWorkRbDescTransType::Rc,
                    pad_cnt: 0,
                },
                addr: 1024,
                len: 1024,
                key: Key::new(0),
                write_type: ToHostWorkRbDescWriteType::First,
                psn: Psn::new(1),
            }),
            // test writeLast
            ToHostWorkRbDesc::Write(ToHostWorkRbDescWrite {
                common: ToHostWorkRbDescCommon {
                    dqpn: Qpn::new(3),
                    status: ToHostWorkRbDescStatus::Normal,
                    trans: ToHostWorkRbDescTransType::Rc,
                    pad_cnt: 0,
                },
                addr: 1024,
                len: 1024,
                key: Key::new(0),
                write_type: ToHostWorkRbDescWriteType::First,
                psn: Psn::new(2),
            }),
            // test read
            ToHostWorkRbDesc::Read(ToHostWorkRbDescRead {
                common: ToHostWorkRbDescCommon {
                    dqpn: Qpn::new(3),
                    status: ToHostWorkRbDescStatus::Normal,
                    trans: ToHostWorkRbDescTransType::Rc,
                    pad_cnt: 0,
                },
                len: 2048,
                laddr: 0,
                lkey: Key::new(0),
                raddr: 0,
                rkey: Key::new(0),
            }),
            ToHostWorkRbDesc::Ack(ToHostWorkRbDescAck {
                common: ToHostWorkRbDescCommon {
                    dqpn: Qpn::new(3),
                    status: ToHostWorkRbDescStatus::Normal,
                    trans: ToHostWorkRbDescTransType::Rc,
                    pad_cnt: 0,
                },
                value: 0,
                msn: Msn::default(),
                psn: Psn::new(2),
            }),
        ];
        input.reverse();

        let work_rb = Arc::new(MockToHostRb::new(input));
        let recv_pkt_map = Arc::new(RwLock::new(HashMap::new()));
        let qp_table = Arc::new(RwLock::new(HashMap::new()));
        qp_table.write().unwrap().insert(
            Qpn::new(3),
            QpContext {
                handle: 0,
                pd: Pd { handle: 0 },
                qpn: Qpn::new(3),
                qp_type: crate::types::QpType::Rc,
                rq_acc_flags: MemAccessTypeFlag::IbvAccessRemoteWrite,
                pmtu: crate::types::Pmtu::Mtu1024,
                dqp_ip: Ipv4Addr::LOCALHOST,
                mac_addr: [0; 6],
                inner: Mutex::new(crate::qp::QpInner {
                    send_psn: Psn::new(0),
                    recv_psn: Psn::new(0),
                }),
            },
        );
        let (sending_queue, recv_queue) = std::sync::mpsc::channel::<RespCommand>();
        let write_op_ctx_map = Arc::new(RwLock::new(HashMap::new()));
        let key = QpnWithLastPsn::new(Qpn::new(3), Psn::new(2));
        let ctx = WriteOpCtx::new_running();
        write_op_ctx_map.write().unwrap().insert(key,ctx.clone());
        let _poller = WorkDescPoller::new(work_rb, recv_pkt_map, qp_table, sending_queue,write_op_ctx_map);
        ctx.wait();
        let item = recv_queue.recv().unwrap();
        match item {
            RespCommand::ReadResponse(res) => {
                assert_eq!(res.desc.len, 2048);
                assert_eq!(res.desc.laddr, 0);
                assert_eq!(res.desc.lkey, Key::new(0));
                assert_eq!(res.desc.raddr, 0);
                assert_eq!(res.desc.rkey, Key::new(0));
            }
            _ => panic!("unexpected item"),
        }
        
    }
}
