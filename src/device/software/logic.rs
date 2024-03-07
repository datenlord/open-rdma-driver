use thiserror::Error;

use crate::device::{
    MemAccessTypeFlag, Pmtu, QpType, QpTypeToTransTypeError, RdmaOpcode, RdmaReqStatus,
    ScatterGatherList, ToCardCtrlRbDesc, ToCardWorkRbDesc, ToCardWorkRbDescOpcode,
    ToHostWorkRbDesc, ToHostWorkRbDescBthAeth, ToHostWorkRbDescBthRethImmDt,
    ToHostWorkRbDescFragAeth, ToHostWorkRbDescFragBth, ToHostWorkRbDescFragImmDt,
    ToHostWorkRbDescFragReth, ToHostWorkRbDescFragSecondaryReth, ToHostWorkRbDescSecondaryReth,
    ToHostWorkRbDescType, TransType,
};

use super::{
    net_agent::{NetAgentError, NetReceiveLogic, NetSendAgent},
    types::{
        Key, Metadata, PDHandle, PKey, PayloadInfo, Psn, Qpn, RdmaGeneralMeta, RdmaMessage,
        RdmaMessageMetaCommon, RethHeader,
    },
    utils::{get_first_packet_length, get_pmtu},
};
use std::{
    collections::HashMap,
    net::Ipv4Addr,
    sync::{Arc, PoisonError, RwLock},
};

#[allow(dead_code)]
struct QueuePairInner {
    pmtu: Pmtu,
    qp_type: QpType,
    qp_access_flags: MemAccessTypeFlag,
    pdkey: PDHandle,
}

/// The hardware queue pair context
struct QueuePair {
    inner: RwLock<QueuePairInner>,
    // recv: RecvRingbuf,
}

/// The hardware memory region context
#[allow(dead_code)]
struct MemoryRegion {
    lkey: Key,
    rkey: Key,
    acc_flags: MemAccessTypeFlag,
    pdkey: PDHandle,
    addr: u64,
    len: usize,
    pgt_offset: u32,
}

/// The simulating hardware logic of BlueRDMA
/// 
/// Typically, the logic needs a `NetSendAgent` and a `NetReceiveAgent` to send and receive packets.
/// User use the `send` method to send a `ToCardWorkRbDesc` to the network, and use the `update` method to update the hardware context.
/// And when the `recv_agent` is binded, the received packets will be parsed and be pushed to the `to_host_data_descriptor_queue`.
/// 
/// # Examples
/// ```
/// let send_agent = UDPSendAgent::new().unwrap();
/// let device = Arc::new(BlueRDMALogic::new(Arc::new(send_agent)));
/// let mut recv_agent = UDPReceiveAgent::new(device.clone()).unwrap();
/// recv_agent.start().unwrap();
/// ```
/// 
/// 
pub(crate) struct BlueRDMALogic {
    mr_rkey_table: RwLock<HashMap<Key, Arc<RwLock<MemoryRegion>>>>,
    qp_table: RwLock<HashMap<Qpn, Arc<QueuePair>>>,
    net_send_agent: Arc<dyn NetSendAgent>,
    to_host_data_descriptor_queue: Arc<crossbeam_queue::SegQueue<ToHostWorkRbDesc>>,
}

#[derive(Error, Debug)]
pub enum BlueRdmaLogicError {
    #[error("packet process error")]
    NetAgentError(#[from] NetAgentError),
    #[error("convert qp type to transport type error")]
    QpTypeToTransTypeError(#[from] QpTypeToTransTypeError),
    #[error("Raw packet length is too long. Pmtu is `{0}`, length is `{1}`")]
    RawPacketLengthTooLong(u32, u32),
    #[error("Poison error")]
    Poison,
}

impl<T> From<PoisonError<T>> for BlueRdmaLogicError {
    fn from(_err: PoisonError<T>) -> Self {
        Self::Poison
    }
}

impl BlueRDMALogic {
    pub fn new(net_sender: Arc<dyn NetSendAgent>) -> Self {
        BlueRDMALogic {
            // mr_lkey_table: RwLock::new(HashMap::new()),
            mr_rkey_table: RwLock::new(HashMap::new()),
            qp_table: RwLock::new(HashMap::new()),
            net_send_agent: net_sender,
            to_host_data_descriptor_queue: Arc::new(crossbeam_queue::SegQueue::new()),
        }
    }

    /// Get the queue that contains the received meta descriptor
    pub fn get_to_host_descriptor_queue(&self) -> Arc<crossbeam_queue::SegQueue<ToHostWorkRbDesc>> {
        self.to_host_data_descriptor_queue.clone()
    }

    /// Convert a `ToCardWorkRbDesc` to a `RdmaMessage` and call the `net_send_agent` to send through the network.
    pub fn send(&self, desc: ToCardWorkRbDesc) -> Result<(), BlueRdmaLogicError> {
        match desc {
            ToCardWorkRbDesc::Request(mut req) => {
                if !req.common_header.valid {
                    return Ok(());
                }

                // if it's a raw packet, send it directly
                if matches!(req.qp_type, QpType::RawPacket) {
                    let total_length = req.common_header.total_len;
                    let pmtu = get_pmtu(&req.pmtu);
                    if total_length > pmtu {
                        return Err(BlueRdmaLogicError::RawPacketLengthTooLong(
                            pmtu,
                            total_length,
                        ));
                    }
                    let mut payload = PayloadInfo::new();
                    let mut cur_level = 0;
                    cut_from_sgl(total_length, &mut req.sgl, &mut cur_level, &mut payload);
                    self.net_send_agent.send_raw(req.dqp_ip, 4791, &payload)?;
                    return Ok(());
                }

                let mut common_meta = RdmaMessageMetaCommon {
                    tran_type: TransType::Rc,
                    opcode: RdmaOpcode::RdmaWriteOnly,
                    solicited: false,
                    pkey: PKey::new(1),
                    dqpn: Qpn::new(req.dqpn),
                    ack_req: false,
                    psn: Psn::new(req.psn),
                };

                match req.common_header.opcode {
                    ToCardWorkRbDescOpcode::RdmaWrite
                    | ToCardWorkRbDescOpcode::RdmaWriteWithImm
                    | ToCardWorkRbDescOpcode::RdmaReadResp => {
                        let is_read_resp = matches!(
                            req.common_header.opcode,
                            ToCardWorkRbDescOpcode::RdmaReadResp
                        );
                        let total_len = req.common_header.total_len;
                        let pmtu = get_pmtu(&req.pmtu);
                        let first_packet_length = get_first_packet_length(req.raddr, pmtu);
                        common_meta.tran_type = req.qp_type.try_into()?;

                        // a default metadata. It will be updated later
                        let mut meta_data = RdmaGeneralMeta {
                            common_meta,
                            reth: RethHeader {
                                va: req.raddr,
                                rkey: Key::new(req.rkey),
                                len: req.common_header.total_len,
                            },
                            imm: None,
                            secondary_reth: None,
                        };

                        if total_len <= first_packet_length {
                            // RdmaWriteOnly or RdmaWriteOnlyWithImmediate
                            let mut payload = PayloadInfo::new();
                            cut_sgl_all_levels(&mut req.sgl, &mut payload);

                            // if it's a RdmaWriteOnlyWithImmediate, add the immediate data
                            let (opcode, imm) = match req.common_header.opcode {
                                ToCardWorkRbDescOpcode::RdmaWriteWithImm => {
                                    (RdmaOpcode::RdmaWriteOnlyWithImmediate, Some(req.imm))
                                }
                                ToCardWorkRbDescOpcode::RdmaWrite => {
                                    (RdmaOpcode::RdmaWriteOnly, None)
                                }
                                ToCardWorkRbDescOpcode::RdmaReadResp => {
                                    (RdmaOpcode::RdmaReadResponseOnly, None)
                                }
                                _ => unreachable!(),
                            };
                            meta_data.common_meta.opcode = opcode;
                            meta_data.imm = imm;

                            let msg = RdmaMessage {
                                meta_data: Metadata::General(meta_data),
                                payload,
                            };

                            self.net_send_agent.send(req.dqp_ip, 4791, &msg)?;
                            return Ok(());
                        }
                        // othetrwise send the data in multiple packets
                        // we specifically handle the first and last packet
                        // The first va might not align to pmtu
                        let mut cur_va = req.raddr;
                        let mut cur_len = total_len;
                        let mut cur_sgl_level = 0;
                        let mut psn: u32 = req.psn;

                        let mut payload = PayloadInfo::new();
                        cut_from_sgl(
                            first_packet_length,
                            &mut req.sgl,
                            &mut cur_sgl_level,
                            &mut payload,
                        );
                        meta_data.common_meta.opcode = if is_read_resp {
                            RdmaOpcode::RdmaReadResponseFirst
                        } else {
                            RdmaOpcode::RdmaWriteFirst
                        };
                        meta_data.reth.va = cur_va;
                        let msg = RdmaMessage {
                            meta_data: Metadata::General(meta_data.clone()),
                            payload,
                        };
                        cur_len -= first_packet_length;
                        psn += 1;
                        cur_va += first_packet_length as u64;
                        self.net_send_agent.send(req.dqp_ip, 4791, &msg)?;

                        // send the middle packets
                        while cur_len > pmtu {
                            let mut payload = PayloadInfo::new();
                            cut_from_sgl(pmtu, &mut req.sgl, &mut cur_sgl_level, &mut payload);
                            meta_data.common_meta.opcode = if is_read_resp {
                                RdmaOpcode::RdmaReadResponseMiddle
                            } else {
                                RdmaOpcode::RdmaWriteMiddle
                            };
                            meta_data.reth.va = cur_va;
                            meta_data.common_meta.psn = Psn::new(psn);
                            let msg = RdmaMessage {
                                meta_data: Metadata::General(meta_data.clone()),
                                payload,
                            };
                            cur_len -= pmtu;
                            psn += 1;
                            cur_va += pmtu as u64;
                            self.net_send_agent.send(req.dqp_ip, 4791, &msg)?;
                        }
                        // cur_len <= pmtu, send last packet
                        let mut payload = PayloadInfo::new();
                        cut_from_sgl(cur_len, &mut req.sgl, &mut cur_sgl_level, &mut payload);
                        // The last packet may be with immediate data
                        let (opcode, imm) = match req.common_header.opcode {
                            ToCardWorkRbDescOpcode::RdmaWriteWithImm => {
                                (RdmaOpcode::RdmaWriteLastWithImmediate, Some(req.imm))
                            }
                            ToCardWorkRbDescOpcode::RdmaWrite => (RdmaOpcode::RdmaWriteLast, None),
                            ToCardWorkRbDescOpcode::RdmaReadResp => {
                                (RdmaOpcode::RdmaReadResponseLast, None)
                            }
                            _ => unreachable!(),
                        };
                        meta_data.common_meta.opcode = opcode;
                        meta_data.common_meta.psn = Psn::new(psn);
                        meta_data.imm = imm;
                        meta_data.reth.va = cur_va;
                        let msg = RdmaMessage {
                            meta_data: Metadata::General(meta_data),
                            payload,
                        };
                        self.net_send_agent.send(req.dqp_ip, 4791, &msg)?;
                    }
                    ToCardWorkRbDescOpcode::RdmaRead => {
                        assert!(req.sgl.len == 1);
                        let local_sa = &req.sgl.data[0];
                        common_meta.opcode = RdmaOpcode::RdmaReadRequest;
                        common_meta.tran_type = req.qp_type.try_into()?;

                        let msg = RdmaMessage {
                            meta_data: Metadata::General(RdmaGeneralMeta {
                                common_meta,
                                reth: RethHeader {
                                    va: req.raddr,
                                    rkey: Key::new(req.rkey),
                                    len: req.common_header.total_len,
                                },
                                imm: None,
                                secondary_reth: Some(RethHeader {
                                    va: local_sa.laddr,
                                    rkey: Key::new(local_sa.lkey),
                                    len: local_sa.len,
                                }),
                            }),
                            payload: PayloadInfo::new(),
                        };

                        self.net_send_agent.send(req.dqp_ip, 4791, &msg)?;
                    }
                    _ => {
                        unimplemented!()
                    }
                }
            }
        }
        Ok(())
    }

    pub fn update(&self, desc: ToCardCtrlRbDesc) ->Result<(),BlueRdmaLogicError> {
        if !desc.common_header().valid {
            return Ok(());
        }
        match desc {
            ToCardCtrlRbDesc::QpManagement(desc) => {
                let mut qp_table = self.qp_table.write()?;
                let qpn = Qpn::new(desc.qpn);
                let qp_inner = QueuePairInner {
                    pmtu: desc.pmtu,
                    qp_type: desc.qp_type,
                    qp_access_flags: MemAccessTypeFlag::from_bits_truncate(desc.rq_access_flags),
                    pdkey: PDHandle::new(desc.pd_handler),
                };
                if let Some(qp_context) = qp_table.get(&qpn) {
                    // update pd_handler, qp_type and access_flags
                    let mut guard = qp_context.inner.write()?;
                    *guard = qp_inner;
                } else {
                    // otherwise insert a new qp context
                    let qp = Arc::new(QueuePair {
                        inner: RwLock::new(qp_inner),
                    });
                    qp_table.insert(qpn, qp);
                }
                Ok(())
            }
            ToCardCtrlRbDesc::UpdateMrTable(desc) => {
                let mut mr_table = self.mr_rkey_table.write()?;
                let rkey = Key::new(desc.mr_key.to_be_bytes());
                let mr = MemoryRegion {
                    lkey: Key::new([0; 4]),
                    rkey,
                    acc_flags: MemAccessTypeFlag::from_bits_truncate(desc.acc_flags),
                    pdkey: PDHandle::new(desc.pd_handler),
                    addr: desc.base_va,
                    len: desc.mr_length as usize,
                    pgt_offset: desc.pgt_offset,
                };
                if let Some(mr_context) = mr_table.get(&mr.rkey) {
                    let mut guard = mr_context.write()?;
                    *guard = mr;
                } else {
                    let mr = Arc::new(RwLock::new(mr));
                    mr_table.insert(rkey, mr);
                }
                Ok(())
            }
            // Userspace device use virtual address directly
            ToCardCtrlRbDesc::UpdatePageTable(_desc) => unimplemented!(),
        }
        // TODO: the form of returned descriptor is not certain
    }

    /// Validate the permission, va and length of corresponding memory region.
    ///
    /// The function will check the following things:
    /// * if the rkey is valid. If not, return `InvMrKey`
    /// * if the permission is valid. If not, return `InvAccFlag`
    /// * if the va and length are valid. If not, return `InvMrRegion`
    /// Otherwise, return `RDMA_REQ_ST_NORMAL`
    fn validate_rkey(
        &self,
        rkey: &Key,
        needed_permissions: MemAccessTypeFlag,
        va: u64,
        length: u32,
    ) -> Result<RdmaReqStatus,BlueRdmaLogicError> {
        let mr_rkey_table = self.mr_rkey_table.read()?;
        let mr = mr_rkey_table.get(rkey);
        if mr.is_none() {
            return Ok(RdmaReqStatus::InvMrKey);
        }
        let read_guard = mr.unwrap().read().unwrap();

        // check the permission.
        if !read_guard.acc_flags.contains(needed_permissions) {
            return Ok(RdmaReqStatus::InvAccFlag);
        }

        // check if the va and length are valid.
        if read_guard.addr > va || read_guard.addr + (read_guard.len as u64) < va + length as u64 {
            return Ok(RdmaReqStatus::InvMrRegion);
        }
        Ok(RdmaReqStatus::Normal)
    }
}

unsafe impl Send for BlueRDMALogic {}
unsafe impl Sync for BlueRDMALogic {}

impl NetReceiveLogic<'_> for BlueRDMALogic {
    fn recv(&self, message: &mut RdmaMessage) {
        let meta = &message.meta_data;
        let descriptor = match meta {
            Metadata::General(header) => {
                // validate the rkey
                let reky = header.reth.rkey;
                let needed_permissions = header.needed_permissions();
                let va = header.reth.va;
                let len = header.reth.len;
                let status = self.validate_rkey(&reky, needed_permissions, va, len).unwrap();

                // Copy the payload to the memory
                if status.is_ok() && header.has_payload() {
                    let va = header.reth.va as usize;
                    message.payload.copy_to(va as *mut u8);
                }

                // Write a descriptor to host
                match header.common_meta.opcode {
                    RdmaOpcode::RdmaWriteFirst
                    | RdmaOpcode::RdmaWriteMiddle
                    | RdmaOpcode::RdmaWriteLast
                    | RdmaOpcode::RdmaWriteOnly
                    | RdmaOpcode::RdmaReadResponseFirst
                    | RdmaOpcode::RdmaReadResponseMiddle
                    | RdmaOpcode::RdmaReadResponseLast
                    | RdmaOpcode::RdmaReadResponseOnly => {
                        ToHostWorkRbDesc::BthRethImmDt(ToHostWorkRbDescBthRethImmDt {
                            desc_type: ToHostWorkRbDescType::RecvPacketMeta,
                            req_status: status,
                            bth: ToHostWorkRbDescFragBth {
                                trans: header.common_meta.tran_type,
                                opcode: header.common_meta.opcode,
                                dqpn: header.common_meta.dqpn.get(),
                                psn: header.common_meta.psn.get(),
                                solicited: header.common_meta.solicited,
                                ack_req: header.common_meta.ack_req,
                            },
                            reth: ToHostWorkRbDescFragReth {
                                va: header.reth.va,
                                rkey: header.reth.rkey.get(),
                                dlen: header.reth.len,
                            },
                            imm_dt: ToHostWorkRbDescFragImmDt { data: [0u8; 4] },
                        })
                    }
                    RdmaOpcode::RdmaWriteLastWithImmediate
                    | RdmaOpcode::RdmaWriteOnlyWithImmediate => {
                        ToHostWorkRbDesc::BthRethImmDt(ToHostWorkRbDescBthRethImmDt {
                            desc_type: ToHostWorkRbDescType::RecvPacketMeta,
                            req_status: status,
                            bth: ToHostWorkRbDescFragBth {
                                trans: header.common_meta.tran_type,
                                opcode: header.common_meta.opcode,
                                dqpn: header.common_meta.dqpn.get(),
                                psn: header.common_meta.psn.get(),
                                solicited: header.common_meta.solicited,
                                ack_req: header.common_meta.ack_req,
                            },
                            reth: ToHostWorkRbDescFragReth {
                                va: header.reth.va,
                                rkey: header.reth.rkey.get(),
                                dlen: header.reth.len,
                            },
                            imm_dt: ToHostWorkRbDescFragImmDt {
                                data: header.imm.unwrap(),
                            },
                        })
                    }
                    RdmaOpcode::RdmaReadRequest => {
                        let sec_reth = header.secondary_reth.unwrap();
                        ToHostWorkRbDesc::SecondaryReth(ToHostWorkRbDescSecondaryReth {
                            sec_reth: ToHostWorkRbDescFragSecondaryReth {
                                secondary_va: sec_reth.va,
                                secondary_rkey: sec_reth.rkey.get(),
                            },
                        })
                    }
                    _ => {
                        unimplemented!()
                    }
                }
            }
            Metadata::Acknowledge(header) => ToHostWorkRbDesc::BthAeth(ToHostWorkRbDescBthAeth {
                desc_type: ToHostWorkRbDescType::RecvPacketMeta,
                req_status: RdmaReqStatus::Normal,
                bth: ToHostWorkRbDescFragBth {
                    trans: header.common_meta.tran_type,
                    opcode: header.common_meta.opcode,
                    dqpn: header.common_meta.dqpn.get(),
                    psn: header.common_meta.psn.get(),
                    solicited: header.common_meta.solicited,
                    ack_req: header.common_meta.ack_req,
                },
                aeth: ToHostWorkRbDescFragAeth {
                    last_retry_psn: 0,
                    msn: header.msn,
                    value: header.aeth_value,
                    code: header.aeth_code,
                },
            }),
        };

        // push the descriptor to the ring buffer
        self.to_host_data_descriptor_queue.push(descriptor);
    }

    fn get_recv_addr(&self) -> Ipv4Addr {
        Ipv4Addr::LOCALHOST
    }

    fn get_recv_port(&self) -> u16 {
        4791
    }
}

/// Cut a buffer of length from the scatter-gather list
///
/// The function iterate from `cur_level` of the scatter-gather list and cut the buffer of `length` from the list.
/// If current level is not enough, it will move to the next level.
/// All the slice will be added to the `payload`.
fn cut_from_sgl(
    mut length: u32,
    sgl: &mut ScatterGatherList,
    external_cur_level: &mut u32,
    payload: &mut PayloadInfo,
) {
    let mut current_level = *external_cur_level as usize;
    while (current_level as u32) < sgl.len {
        if sgl.data[current_level].len >= length {
            let addr = sgl.data[current_level].laddr as *mut u8;
            payload.add(addr, length as usize);
            sgl.data[current_level].laddr += length as u64;
            sgl.data[current_level].len -= length;
            if sgl.data[current_level].len == 0 {
                current_level += 1;
                *external_cur_level = current_level as u32;
            }
            return;
        } else {
            // check next level
            let addr = sgl.data[current_level].laddr as *mut u8;
            payload.add(addr, sgl.data[current_level].len as usize);
            length -= sgl.data[current_level].len;
            sgl.data[current_level].len = 0;
            current_level += 1;
        }
    }
    if (current_level as u32) == sgl.len {
        unreachable!("The length is too long");
    }
}

/// Cut all the buffer to `payload``
fn cut_sgl_all_levels(sgl: &mut ScatterGatherList, payload: &mut PayloadInfo) {
    for i in 0..sgl.len as usize {
        let addr = sgl.data[i].laddr as *mut u8;
        let length = sgl.data[i].len as usize;
        payload.add(addr, length);
        sgl.data[i].len = 0;
    }
}

#[cfg(test)]
mod tests {
    use std::{net::Ipv4Addr, sync::Arc};

    use crate::device::{
        software::{
            logic::cut_sgl_all_levels,
            net_agent::{NetAgentError, NetSendAgent},
            types::{Key, PayloadInfo, Qpn, RdmaMessage},
        },
        CtrlRbDescCommonHeader, CtrlRbDescOpcode, MemAccessTypeFlag, Pmtu, QpType,
        ScatterGatherElement, ScatterGatherList, ToCardCtrlRbDesc, ToCardCtrlRbDescQpManagement,
        ToCardCtrlRbDescUpdateMrTable,
    };

    use super::{cut_from_sgl, BlueRDMALogic};

    #[test]
    fn test_helper_cut_from_sgl() {
        // Here we don't care the va boundary
        // test: has [1000,0,0,0], request 1000
        {
            let mut sgl = ScatterGatherList {
                data: [ScatterGatherElement {
                    laddr: 0x1000,
                    len: 1000,
                    lkey: 0_u32.to_be_bytes(),
                }; 4],
                len: 1,
            };
            let mut payload = PayloadInfo::new();
            let mut cur_level = 0;
            cut_from_sgl(1000, &mut sgl, &mut cur_level, &mut payload);
            assert_eq!(payload.get_length(), 1000);
            assert_eq!(sgl.data[0].len, 0);
            assert_eq!(cur_level, 1);
        }

        // test has [1000,0,0,0], request 1000
        {
            let mut sgl = ScatterGatherList {
                data: [ScatterGatherElement {
                    laddr: 0x1000,
                    len: 1000,
                    lkey: 0_u32.to_be_bytes(),
                }; 4],
                len: 1,
            };
            let mut payload = PayloadInfo::new();
            let mut cur_level = 0;
            cut_from_sgl(900, &mut sgl, &mut cur_level, &mut payload);
            assert_eq!(payload.get_length(), 900);
            assert_eq!(sgl.data[0].len, 100);
            assert_eq!(cur_level, 0);
        }

        // test has [1024,0,0,0], request 512,512
        {
            let mut sgl = ScatterGatherList {
                data: [ScatterGatherElement {
                    laddr: 0x1000,
                    len: 1024,
                    lkey: 0_u32.to_be_bytes(),
                }; 4],
                len: 1,
            };
            let mut payload1 = PayloadInfo::new();
            let mut payload2 = PayloadInfo::new();
            let mut cur_level = 0;
            cut_from_sgl(512, &mut sgl, &mut cur_level, &mut payload1);
            cut_from_sgl(512, &mut sgl, &mut cur_level, &mut payload2);
            assert_eq!(payload1.get_length(), 512);
            assert_eq!(payload2.get_length(), 512);
            assert_eq!(sgl.data[0].len, 0);
            assert_eq!(cur_level, 1);
            assert_eq!(payload1.get_sg_list().first().unwrap().data as u64, 0x1000);
            assert_eq!(
                payload2.get_sg_list().first().unwrap().data as u64,
                0x1000 + 512
            );
        }

        // test has [1024,1024,0,0], require 2048
        {
            let mut sgl = ScatterGatherList {
                data: [
                    ScatterGatherElement {
                        laddr: 0x1000,
                        len: 1024,
                        lkey: 0_u32.to_be_bytes(),
                    },
                    ScatterGatherElement {
                        laddr: 0x3000,
                        len: 1024,
                        lkey: 0_u32.to_be_bytes(),
                    },
                    ScatterGatherElement {
                        laddr: 0,
                        len: 0,
                        lkey: 0_u32.to_be_bytes(),
                    },
                    ScatterGatherElement {
                        laddr: 0,
                        len: 0,
                        lkey: 0_u32.to_be_bytes(),
                    },
                ],
                len: 2,
            };
            let mut payload = PayloadInfo::new();
            let mut cur_level = 0;
            cut_from_sgl(2048, &mut sgl, &mut cur_level, &mut payload);
            assert_eq!(payload.get_length(), 2048);
            assert_eq!(sgl.data[0].len, 0);
            assert_eq!(sgl.data[1].len, 0);
            assert_eq!(cur_level, 2);
            assert_eq!(payload.get_sg_list()[0].data as u64, 0x1000);
            assert_eq!(payload.get_sg_list()[0].len as u64, 1024);
            assert_eq!(payload.get_sg_list()[1].data as u64, 0x3000);
            assert_eq!(payload.get_sg_list()[1].len as u64, 1024);
        }

        // test has [1024,2048,1124,100], require [100,2048,2048,100]
        {
            let mut sgl = ScatterGatherList {
                data: [
                    ScatterGatherElement {
                        laddr: 0x1000,
                        len: 1024,
                        lkey: 0_u32.to_be_bytes(),
                    },
                    ScatterGatherElement {
                        laddr: 0x3000,
                        len: 2048,
                        lkey: 0_u32.to_be_bytes(),
                    },
                    ScatterGatherElement {
                        laddr: 0x6000,
                        len: 1124,
                        lkey: 0_u32.to_be_bytes(),
                    },
                    ScatterGatherElement {
                        laddr: 0x8000,
                        len: 100,
                        lkey: 0_u32.to_be_bytes(),
                    },
                ],
                len: 4,
            };
            let mut payload = [
                PayloadInfo::new(),
                PayloadInfo::new(),
                PayloadInfo::new(),
                PayloadInfo::new(),
            ];
            let mut cur_level = 0;
            cut_from_sgl(100, &mut sgl, &mut cur_level, &mut payload[0]);
            cut_from_sgl(2048, &mut sgl, &mut cur_level, &mut payload[1]);
            cut_from_sgl(2048, &mut sgl, &mut cur_level, &mut payload[2]);
            cut_from_sgl(100, &mut sgl, &mut cur_level, &mut payload[3]);
            assert_eq!(payload[0].get_length(), 100);
            assert_eq!(payload[1].get_length(), 2048);
            assert_eq!(payload[2].get_length(), 2048);
            assert_eq!(payload[3].get_length(), 100);
            assert_eq!(sgl.data[0].len, 0);
            assert_eq!(sgl.data[1].len, 0);
            assert_eq!(sgl.data[2].len, 0);
            assert_eq!(sgl.data[3].len, 0);
        }
    }

    #[test]
    fn test_helper_cut_sgl_all() {
        let mut sgl = ScatterGatherList {
            data: [ScatterGatherElement {
                laddr: 0x1000,
                len: 1024,
                lkey: 0_u32.to_be_bytes(),
            }; 4],
            len: 4,
        };
        let mut payload = PayloadInfo::new();
        cut_sgl_all_levels(&mut sgl, &mut payload);
        assert_eq!(sgl.data[0].len, 0);
        assert_eq!(sgl.data[1].len, 0);
        assert_eq!(sgl.data[2].len, 0);
        assert_eq!(sgl.data[3].len, 0);
        assert_eq!(payload.get_length(), 4096);
    }

    // test update mr table, qp table
    #[test]
    fn test_logic_update() {
        struct DummpyProxy;

        impl NetSendAgent for DummpyProxy {
            fn send(
                &self,
                _: Ipv4Addr,
                _: u16,
                _message: &RdmaMessage,
            ) -> Result<(), NetAgentError> {
                Ok(())
            }

            fn send_raw(
                &self,
                _: Ipv4Addr,
                _: u16,
                _payload: &PayloadInfo,
            ) -> Result<(), NetAgentError> {
                Ok(())
            }

            fn get_dest_addr(&self) -> Ipv4Addr {
                Ipv4Addr::LOCALHOST
            }

            fn get_dest_port(&self) -> u16 {
                4791
            }
        }
        let agent = Arc::new(DummpyProxy);
        let logic = BlueRDMALogic::new(agent.clone());
        // test updating qp
        {
            let desc = ToCardCtrlRbDesc::QpManagement(ToCardCtrlRbDescQpManagement {
                common_header: CtrlRbDescCommonHeader {
                    valid: true,
                    opcode: CtrlRbDescOpcode::UpdateMrTable,
                    extra_segment_cnt: 0,
                    is_success_or_need_signal_cplt: false,
                    user_data: [0; 4],
                },
                is_valid: true,
                is_error: true,
                qpn: 1234,
                pd_handler: 1,
                qp_type: QpType::Rc,
                rq_access_flags: MemAccessTypeFlag::IbvAccessRemoteWrite.bits(),
                pmtu: Pmtu::Mtu1024,
            });
            logic.update(desc).unwrap();
            {
                let guard = logic.qp_table.read().unwrap();
                let qp_context = guard.get(&Qpn::new(1234)).unwrap();
                let read_guard = qp_context.inner.read().unwrap();
                assert_eq!(read_guard.pmtu, Pmtu::Mtu1024);
                assert_eq!(read_guard.qp_type, QpType::Rc);
                assert!(read_guard
                    .qp_access_flags
                    .contains(MemAccessTypeFlag::IbvAccessRemoteWrite));
            }

            // write again
            let desc = ToCardCtrlRbDesc::QpManagement(ToCardCtrlRbDescQpManagement {
                common_header: CtrlRbDescCommonHeader {
                    valid: true,
                    opcode: CtrlRbDescOpcode::UpdateMrTable,
                    extra_segment_cnt: 0,
                    is_success_or_need_signal_cplt: false,
                    user_data: [0; 4],
                },
                is_valid: true,
                is_error: true,
                qpn: 1234,
                pd_handler: 1,
                qp_type: QpType::Rc,
                rq_access_flags: MemAccessTypeFlag::IbvAccessRemoteWrite.bits(),
                pmtu: Pmtu::Mtu2048,
            });
            logic.update(desc).unwrap();
            {
                let guard = logic.qp_table.read().unwrap();
                let qp_context = guard.get(&Qpn::new(1234)).unwrap();
                let read_guard = qp_context.inner.read().unwrap();
                assert_eq!(read_guard.pmtu, Pmtu::Mtu2048);
                assert_eq!(read_guard.qp_type, QpType::Rc);
                assert!(read_guard
                    .qp_access_flags
                    .contains(MemAccessTypeFlag::IbvAccessRemoteWrite));
            }
        }

        // test updating mr
        {
            let desc = ToCardCtrlRbDesc::UpdateMrTable(ToCardCtrlRbDescUpdateMrTable {
                common_header: CtrlRbDescCommonHeader {
                    valid: true,
                    opcode: CtrlRbDescOpcode::UpdateMrTable,
                    extra_segment_cnt: 0,
                    is_success_or_need_signal_cplt: false,
                    user_data: [0; 4],
                },
                base_va: 0x1234567812345678,
                mr_length: 1024 * 16,
                mr_key: 1234,
                pd_handler: 0,
                acc_flags: MemAccessTypeFlag::IbvAccessRemoteWrite.bits(),
                pgt_offset: 0,
            });
            logic.update(desc).unwrap();
            {
                let guard = logic.mr_rkey_table.read().unwrap();
                let mr_context = guard.get(&Key::new(1234_u32.to_be_bytes())).unwrap();
                let read_guard = mr_context.read().unwrap();
                assert_eq!(read_guard.addr, 0x1234567812345678);
                assert_eq!(read_guard.len, 1024 * 16);
                assert_eq!(read_guard.pdkey.get(), 0);
                assert!(read_guard
                    .acc_flags
                    .contains(MemAccessTypeFlag::IbvAccessRemoteWrite));
                assert_eq!(read_guard.pgt_offset, 0);
            }

            // update again
            let desc = ToCardCtrlRbDesc::UpdateMrTable(ToCardCtrlRbDescUpdateMrTable {
                common_header: CtrlRbDescCommonHeader {
                    valid: true,
                    opcode: CtrlRbDescOpcode::UpdateMrTable,
                    extra_segment_cnt: 0,
                    is_success_or_need_signal_cplt: false,
                    user_data: [0; 4],
                },
                base_va: 0x1234567812345678,
                mr_length: 1024 * 24,
                mr_key: 1234,
                pd_handler: 0,
                acc_flags: (MemAccessTypeFlag::IbvAccessRemoteWrite
                    | MemAccessTypeFlag::IbvAccessRemoteRead)
                    .bits(),
                pgt_offset: 0,
            });
            logic.update(desc).unwrap();
            {
                let guard = logic.mr_rkey_table.read().unwrap();
                let mr_context = guard.get(&Key::new(1234_u32.to_be_bytes())).unwrap();
                let read_guard = mr_context.read().unwrap();
                assert_eq!(read_guard.addr, 0x1234567812345678);
                assert_eq!(read_guard.len, 1024 * 24);
                assert_eq!(read_guard.pdkey.get(), 0);
                assert!(read_guard
                    .acc_flags
                    .contains(MemAccessTypeFlag::IbvAccessRemoteWrite));
                assert!(read_guard
                    .acc_flags
                    .contains(MemAccessTypeFlag::IbvAccessRemoteRead));
                assert_eq!(read_guard.pgt_offset, 0);
            }
        }
    }
}
