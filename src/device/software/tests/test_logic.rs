use std::{cell::RefCell, collections::LinkedList, net::Ipv4Addr, sync::Arc};

use crate::device::{
    software::{
        logic::BlueRDMALogic,
        net_agent::{NetAgentError, NetSendAgent},
        types::{Metadata, PayloadInfo, RdmaMessage},
    },
    Pmtu, QpType, RdmaOpcode, ScatterGatherElement, ScatterGatherList, ToCardWorkRbDesc,
    ToCardWorkRbDescCommonHeader, ToCardWorkRbDescOpcode, ToCardWorkRbDescRequest,
};

struct DummpyProxy {
    message: RefCell<LinkedList<RdmaMessage>>,
    payload: RefCell<LinkedList<PayloadInfo>>,
}

impl DummpyProxy {
    fn new() -> Self {
        DummpyProxy {
            message: LinkedList::new().into(),
            payload: LinkedList::new().into(),
        }
    }
}
impl NetSendAgent for DummpyProxy {
    fn send(&self, _: Ipv4Addr, _: u16, message: &RdmaMessage) -> Result<(), NetAgentError> {
        self.message.borrow_mut().push_back(message.clone());
        Ok(())
    }

    fn send_raw(&self, _: Ipv4Addr, _: u16, payload: &PayloadInfo) -> Result<(), NetAgentError> {
        self.payload.borrow_mut().push_back(payload.clone());
        Ok(())
    }

    fn get_dest_addr(&self) -> Ipv4Addr {
        Ipv4Addr::LOCALHOST
    }

    fn get_dest_port(&self) -> u16 {
        4791
    }
}

unsafe impl Send for DummpyProxy {}
unsafe impl Sync for DummpyProxy {}

#[test]
fn test_logic_send() {
    let agent = Arc::new(DummpyProxy::new());
    let logic = BlueRDMALogic::new(agent.clone());

    // expect write_only
    {
        let desc = ToCardWorkRbDesc::Request(ToCardWorkRbDescRequest {
            common_header: ToCardWorkRbDescCommonHeader {
                valid: true,
                opcode: ToCardWorkRbDescOpcode::RdmaWrite,
                is_last: true,
                is_first: true,
                extra_segment_cnt: 0,
                is_success_or_need_signal_cplt: false,
                total_len: 512,
            },
            raddr: 0x0,
            rkey: 1234_u32.to_be_bytes(),
            dqp_ip: Ipv4Addr::new(127, 0, 0, 1),
            pmtu: Pmtu::Mtu1024,
            flags: 0,
            qp_type: QpType::Rc,
            sge_cnt: 0,
            psn: 1234,
            mac_addr: [0u8; 6],
            dqpn: 12,
            imm: [0u8; 4],
            sgl: ScatterGatherList {
                data: [ScatterGatherElement {
                    laddr: 0x1000,
                    len: 512,
                    lkey: 0x1234_u32.to_be_bytes(),
                }; 4],
                len: 1,
            },
        });
        logic.send(desc).unwrap();
        assert_eq!(agent.message.borrow().len(), 1);
        let message = agent.message.borrow_mut().pop_front().unwrap();
        assert_eq!(message.meta_data.get_opcode(), RdmaOpcode::RdmaWriteOnly);
        assert_eq!(message.payload.get_length(), 512);
        assert_eq!(message.payload.get_sg_list()[0].data as u64, 0x1000);
    }

    // va=512,length = 1024, expect write_first + write_last
    {
        let desc = ToCardWorkRbDesc::Request(ToCardWorkRbDescRequest {
            common_header: ToCardWorkRbDescCommonHeader {
                valid: true,
                opcode: ToCardWorkRbDescOpcode::RdmaWrite,
                is_last: true,
                is_first: true,
                extra_segment_cnt: 0,
                is_success_or_need_signal_cplt: false,
                total_len: 1024,
            },
            raddr: 512,
            rkey: 1234_u32.to_be_bytes(),
            dqp_ip: Ipv4Addr::new(127, 0, 0, 1),
            pmtu: Pmtu::Mtu1024,
            flags: 0,
            qp_type: QpType::Rc,
            sge_cnt: 0,
            psn: 1234,
            mac_addr: [0u8; 6],
            dqpn: 12,
            imm: [0u8; 4],
            sgl: ScatterGatherList {
                data: [
                    ScatterGatherElement {
                        laddr: 0x1000,
                        len: 256,
                        lkey: 0x1234_u32.to_be_bytes(),
                    },
                    ScatterGatherElement {
                        laddr: 0x2000,
                        len: 768,
                        lkey: 0x1234_u32.to_be_bytes() ,
                    },
                    ScatterGatherElement {
                        laddr: 0,
                        len: 0,
                        lkey: 0x1234_u32.to_be_bytes() ,
                    },
                    ScatterGatherElement {
                        laddr: 0,
                        len: 0,
                        lkey: 0x1234_u32.to_be_bytes() ,
                    },
                ],
                len: 2,
            },
        });
        logic.send(desc).unwrap();
        assert_eq!(agent.message.borrow().len(), 2);
        let message1 = agent.message.borrow_mut().pop_front().unwrap();
        assert_eq!(message1.meta_data.get_opcode(), RdmaOpcode::RdmaWriteFirst);
        assert_eq!(message1.payload.get_length(), 512);
        let message2 = agent.message.borrow_mut().pop_front().unwrap();
        assert_eq!(message2.meta_data.get_opcode(), RdmaOpcode::RdmaWriteLast);
        assert_eq!(message2.payload.get_length(), 512);
    }

    // va=1023,length = 4096, expect write_first + write_middle + write_middle + write_middle + write_last
    {
        let desc = ToCardWorkRbDesc::Request(ToCardWorkRbDescRequest {
            common_header: ToCardWorkRbDescCommonHeader {
                valid: true,
                opcode: ToCardWorkRbDescOpcode::RdmaWrite,
                is_last: true,
                is_first: true,
                extra_segment_cnt: 0,
                is_success_or_need_signal_cplt: false,
                total_len: 4096,
            },
            raddr: 1023,
            rkey: 1234_u32.to_be_bytes(),
            dqp_ip: Ipv4Addr::new(127, 0, 0, 1),
            pmtu: Pmtu::Mtu1024,
            flags: 0,
            qp_type: QpType::Rc,
            sge_cnt: 0,
            psn: 1234,
            mac_addr: [0u8; 6],
            dqpn: 12,
            imm: [0u8; 4],
            sgl: ScatterGatherList {
                data: [ScatterGatherElement {
                    laddr: 0x1000,
                    len: 4096,
                    lkey: 0x1234_u32.to_be_bytes() ,
                }; 4],
                len: 1,
            },
        });
        logic.send(desc).unwrap();
        assert_eq!(agent.message.borrow().len(), 5);
        let message_first = agent.message.borrow_mut().pop_front().unwrap();
        assert_eq!(
            message_first.meta_data.get_opcode(),
            RdmaOpcode::RdmaWriteFirst
        );
        assert_eq!(message_first.payload.get_length(), 1);
        let message_middle = agent.message.borrow_mut().pop_front().unwrap();
        assert_eq!(
            message_middle.meta_data.get_opcode(),
            RdmaOpcode::RdmaWriteMiddle
        );
        assert_eq!(message_middle.payload.get_length(), 1024);
        let message_middle = agent.message.borrow_mut().pop_front().unwrap();
        assert_eq!(
            message_middle.meta_data.get_opcode(),
            RdmaOpcode::RdmaWriteMiddle
        );
        assert_eq!(message_middle.payload.get_length(), 1024);
        let message_middle = agent.message.borrow_mut().pop_front().unwrap();
        assert_eq!(
            message_middle.meta_data.get_opcode(),
            RdmaOpcode::RdmaWriteMiddle
        );
        assert_eq!(message_middle.payload.get_length(), 1024);
        let message_last = agent.message.borrow_mut().pop_front().unwrap();
        assert_eq!(
            message_last.meta_data.get_opcode(),
            RdmaOpcode::RdmaWriteLast
        );
        assert_eq!(message_last.payload.get_length(), 1023);
    }

    // read, va=1023,length = 4096, expect write_first + write_middle + write_middle + write_middle + write_last
    {
        let desc = ToCardWorkRbDesc::Request(ToCardWorkRbDescRequest {
            common_header: ToCardWorkRbDescCommonHeader {
                valid: true,
                opcode: ToCardWorkRbDescOpcode::RdmaReadResp,
                is_last: true,
                is_first: true,
                extra_segment_cnt: 0,
                is_success_or_need_signal_cplt: false,
                total_len: 4096,
            },
            raddr: 1023,
            rkey: 1234_u32.to_be_bytes(),
            dqp_ip: Ipv4Addr::new(127, 0, 0, 1),
            pmtu: Pmtu::Mtu1024,
            flags: 0,
            qp_type: QpType::Rc,
            sge_cnt: 0,
            psn: 1234,
            mac_addr: [0u8; 6],
            dqpn: 12,
            imm: [0u8; 4],
            sgl: ScatterGatherList {
                data: [ScatterGatherElement {
                    laddr: 0x1000,
                    len: 4096,
                    lkey: 0x1234_u32.to_be_bytes() ,
                }; 4],
                len: 1,
            },
        });
        logic.send(desc).unwrap();
        assert_eq!(agent.message.borrow().len(), 5);
        let message_first = agent.message.borrow_mut().pop_front().unwrap();
        assert_eq!(
            message_first.meta_data.get_opcode(),
            RdmaOpcode::RdmaReadResponseFirst
        );
        assert_eq!(message_first.payload.get_length(), 1);
        let psn1 = message_first.meta_data.get_psn().get();
        let message_middle = agent.message.borrow_mut().pop_front().unwrap();
        assert_eq!(
            message_middle.meta_data.get_opcode(),
            RdmaOpcode::RdmaReadResponseMiddle
        );
        assert_eq!(message_middle.payload.get_length(), 1024);
        let psn2 = message_middle.meta_data.get_psn().get();
        assert!(psn2 == psn1 + 1);
        let message_middle = agent.message.borrow_mut().pop_front().unwrap();
        assert_eq!(
            message_middle.meta_data.get_opcode(),
            RdmaOpcode::RdmaReadResponseMiddle
        );
        assert_eq!(message_middle.payload.get_length(), 1024);
        let psn3 = message_middle.meta_data.get_psn().get();
        assert!(psn3 == psn2 + 1);
        let message_middle = agent.message.borrow_mut().pop_front().unwrap();
        assert_eq!(
            message_middle.meta_data.get_opcode(),
            RdmaOpcode::RdmaReadResponseMiddle
        );
        assert_eq!(message_middle.payload.get_length(), 1024);
        let psn4 = message_middle.meta_data.get_psn().get();
        assert!(psn4 == psn3 + 1);
        let message_last = agent.message.borrow_mut().pop_front().unwrap();
        assert_eq!(
            message_last.meta_data.get_opcode(),
            RdmaOpcode::RdmaReadResponseLast
        );
        assert_eq!(message_last.payload.get_length(), 1023);
    }

    // test write only with imm
    {
        let desc = ToCardWorkRbDesc::Request(ToCardWorkRbDescRequest {
            common_header: ToCardWorkRbDescCommonHeader {
                valid: true,
                opcode: ToCardWorkRbDescOpcode::RdmaWriteWithImm,
                is_last: true,
                is_first: true,
                extra_segment_cnt: 0,
                is_success_or_need_signal_cplt: false,
                total_len: 20,
            },
            raddr: 0,
            rkey: 1234_u32.to_be_bytes(),
            dqp_ip: Ipv4Addr::new(127, 0, 0, 1),
            pmtu: Pmtu::Mtu1024,
            flags: 0,
            qp_type: QpType::Rc,
            sge_cnt: 0,
            psn: 1234,
            mac_addr: [0u8; 6],
            dqpn: 12,
            imm: [0, 0, 0x4, 0xd2], // 1234
            sgl: ScatterGatherList {
                data: [ScatterGatherElement {
                    laddr: 0x1000,
                    len: 20,
                    lkey: 0x1234_u32.to_be_bytes() ,
                }; 4],
                len: 1,
            },
        });
        logic.send(desc).unwrap();
        assert_eq!(agent.message.borrow().len(), 1);
        let message = agent.message.borrow_mut().pop_front().unwrap();
        assert_eq!(
            message.meta_data.get_opcode(),
            RdmaOpcode::RdmaWriteOnlyWithImmediate
        );
        match message.meta_data {
            Metadata::General(meta) => {
                assert_eq!(meta.imm.unwrap(), [0, 0, 0x4, 0xd2]);
            }
            _ => unreachable!(),
        }
    }

    // test read request
    {
        let desc = ToCardWorkRbDesc::Request(ToCardWorkRbDescRequest {
            common_header: ToCardWorkRbDescCommonHeader {
                valid: true,
                opcode: ToCardWorkRbDescOpcode::RdmaRead,
                is_last: true,
                is_first: true,
                extra_segment_cnt: 0,
                is_success_or_need_signal_cplt: false,
                total_len: 1024,
            },
            raddr: 0,
            rkey: 1234_u32.to_be_bytes(),
            dqp_ip: Ipv4Addr::new(127, 0, 0, 1),
            pmtu: Pmtu::Mtu1024,
            flags: 0,
            qp_type: QpType::Rc,
            sge_cnt: 0,
            psn: 1234,
            mac_addr: [0u8; 6],
            dqpn: 12,
            imm: [0u8; 4],
            sgl: ScatterGatherList {
                data: [ScatterGatherElement {
                    laddr: 1000,
                    len: 1024,
                    lkey: 4567_u32.to_be_bytes(),
                }; 4],
                len: 1,
            },
        });
        logic.send(desc).unwrap();
        assert_eq!(agent.message.borrow().len(), 1);
        let message = agent.message.borrow_mut().pop_front().unwrap();
        assert_eq!(message.meta_data.get_opcode(), RdmaOpcode::RdmaReadRequest);
        match message.meta_data {
            Metadata::General(meta) => {
                assert_eq!(meta.reth.va, 0);
                assert_eq!(meta.reth.len, 1024);
                assert_eq!(u32::from_be_bytes(meta.reth.rkey.get()), 1234);
                let secondary_reth = meta.secondary_reth.as_ref().unwrap();
                assert_eq!(secondary_reth.va, 1000);
                assert_eq!(secondary_reth.len, 1024);
                assert_eq!(u32::from_be_bytes(secondary_reth.rkey.get()), 4567);
            }
            _ => unreachable!(),
        }
    }
}

#[test]
fn test_logic_send_raw() {
    let agent = Arc::new(DummpyProxy::new());
    let logic = BlueRDMALogic::new(agent.clone());
    {
        let desc = ToCardWorkRbDesc::Request(ToCardWorkRbDescRequest {
            common_header: ToCardWorkRbDescCommonHeader {
                valid: true,
                opcode: ToCardWorkRbDescOpcode::RdmaRead,
                is_last: true,
                is_first: true,
                extra_segment_cnt: 0,
                is_success_or_need_signal_cplt: false,
                total_len: 4096,
            },
            raddr: 0,
            rkey: 1234_u32.to_be_bytes(),
            dqp_ip: Ipv4Addr::new(127, 0, 0, 1),
            pmtu: Pmtu::Mtu4096,
            flags: 0,
            qp_type: QpType::RawPacket,
            sge_cnt: 0,
            psn: 1234,
            mac_addr: [0u8; 6],
            dqpn: 12,
            imm: [0u8; 4],
            sgl: ScatterGatherList {
                data: [
                    ScatterGatherElement {
                        laddr: 1000,
                        len: 1024,
                        lkey: 4567_u32.to_be_bytes(),
                    },
                    ScatterGatherElement {
                        laddr: 3000,
                        len: 1024,
                        lkey: 4567_u32.to_be_bytes(),
                    },
                    ScatterGatherElement {
                        laddr: 5000,
                        len: 1024,
                        lkey: 4567_u32.to_be_bytes(),
                    },
                    ScatterGatherElement {
                        laddr: 7000,
                        len: 1024,
                        lkey: 4567_u32.to_be_bytes(),
                    },
                ],
                len: 4,
            },
        });
        logic.send(desc).unwrap();
        assert_eq!(agent.payload.borrow().len(), 1);
        let payload = agent.payload.borrow_mut().pop_front().unwrap();
        assert_eq!(payload.get_length(), 4096);
        assert_eq!(payload.get_sg_list()[0].data, 1000 as *const u8);
        assert_eq!(payload.get_sg_list()[1].data, 3000 as *const u8);
        assert_eq!(payload.get_sg_list()[2].data, 5000 as *const u8);
        assert_eq!(payload.get_sg_list()[3].data, 7000 as *const u8);

    }
}
