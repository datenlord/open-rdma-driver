use serial_test::serial;
use std::{net::Ipv4Addr, sync::Arc, thread::sleep, time::Duration};

use crate::device::{
    software::{
        logic::BlueRDMALogic,
        net_agent::udp_agent::{UDPReceiveAgent, UDPSendAgent},
    },
    CtrlRbDescCommonHeader, CtrlRbDescOpcode, DeviceAdaptor, MemAccessTypeFlag, Pmtu, QpType,
    RdmaOpcode, ScatterGatherElement, ScatterGatherList, SoftwareDevice, ToCardCtrlRbDesc,
    ToCardCtrlRbDescQpManagement, ToCardCtrlRbDescUpdateMrTable, ToCardWorkRbDesc,
    ToCardWorkRbDescCommonHeader, ToCardWorkRbDescOpcode, ToCardWorkRbDescRequest,
    ToHostWorkRbDesc,
};

#[test]
#[serial]
fn test_device_read_and_write() {
    let send_agent = UDPSendAgent::new().unwrap();
    let device = Arc::new(BlueRDMALogic::new(Arc::new(send_agent)));
    let mut recv_agent = UDPReceiveAgent::new(device.clone()).unwrap();
    recv_agent.start().unwrap();
    let mr1_rkey = 1234;
    let mr2_rkey = 4321;
    let dqpn = 5;
    let pmtu = 512;
    // create a mr
    let src_buf = [1u8; 4096];
    let src_addr = src_buf.as_ptr() as u64;
    let src_offset = (src_addr - src_buf.as_ptr() as u64) as usize;
    let mut dest_buffer = [0u8; 4096];
    let dest_addr = (dest_buffer.as_ptr() as u64 + pmtu - 1) & !(pmtu - 1);
    let dest_offset = (dest_addr - dest_buffer.as_ptr() as u64) as usize;
    let time_to_wait_in_mill = 100;
    {
        // create mr for write
        let mr_desc = ToCardCtrlRbDesc::UpdateMrTable(ToCardCtrlRbDescUpdateMrTable {
            common_header: CtrlRbDescCommonHeader {
                valid: true,
                opcode: CtrlRbDescOpcode::UpdateMrTable,
                extra_segment_cnt: 0,
                is_success_or_need_signal_cplt: false,
                user_data: [0; 4],
            },
            base_va: dest_addr,
            mr_length: 2048,
            mr_key: mr1_rkey,
            pd_handler: 0,
            acc_flags: (MemAccessTypeFlag::IbvAccessRemoteWrite
                | MemAccessTypeFlag::IbvAccessRemoteRead)
                .bits(),
            pgt_offset: 0,
        });
        device.update(mr_desc).unwrap();

        let mr_desc = ToCardCtrlRbDesc::UpdateMrTable(ToCardCtrlRbDescUpdateMrTable {
            common_header: CtrlRbDescCommonHeader {
                valid: true,
                opcode: CtrlRbDescOpcode::UpdateMrTable,
                extra_segment_cnt: 0,
                is_success_or_need_signal_cplt: false,
                user_data: [0; 4],
            },
            base_va: src_addr,
            mr_length: 2048,
            mr_key: mr2_rkey,
            pd_handler: 0,
            acc_flags: (MemAccessTypeFlag::IbvAccessRemoteWrite
                | MemAccessTypeFlag::IbvAccessRemoteRead)
                .bits(),
            pgt_offset: 0,
        });
        device.update(mr_desc).unwrap();
    }

    {
        // create qp
        let desc = ToCardCtrlRbDesc::QpManagement(ToCardCtrlRbDescQpManagement {
            common_header: CtrlRbDescCommonHeader {
                valid: true,
                opcode: CtrlRbDescOpcode::UpdateMrTable,
                extra_segment_cnt: 0,
                is_success_or_need_signal_cplt: false,
                user_data: [0; 4],
            },
            is_valid: true,
            is_error: false,
            qpn: dqpn,
            pd_handler: 1,
            qp_type: QpType::Rc,
            rq_access_flags: MemAccessTypeFlag::IbvAccessRemoteWrite.bits(),
            pmtu: Pmtu::Mtu512,
        });
        device.update(desc).unwrap();
    }

    // test a align sending
    {
        let send_length = 2 * pmtu;
        let desc = ToCardWorkRbDesc::Request(ToCardWorkRbDescRequest {
            common_header: ToCardWorkRbDescCommonHeader {
                valid: true,
                opcode: ToCardWorkRbDescOpcode::RdmaWrite,
                is_last: true,
                is_first: true,
                extra_segment_cnt: 0,
                is_success_or_need_signal_cplt: false,
                total_len: send_length as u32,
            },
            raddr: dest_addr,
            rkey: mr1_rkey.to_be_bytes(),
            dqp_ip: Ipv4Addr::new(127, 0, 0, 1),
            pmtu: Pmtu::Mtu512,
            flags: 0,
            qp_type: QpType::Rc,
            sge_cnt: 0,
            psn: 1234,
            mac_addr: [0u8; 6],
            dqpn,
            imm: [0u8; 4],
            sgl: ScatterGatherList {
                data: [ScatterGatherElement {
                    laddr: src_addr,
                    len: 1024,
                    lkey: 0_u32.to_be_bytes(),
                }; 4],
                len: 1,
            },
        });

        device.send(desc).unwrap();
        // sync the sending packet
        sleep(Duration::from_millis(time_to_wait_in_mill));
        let q1 = device.get_to_host_descriptor_queue().pop().unwrap();
        match q1 {
            ToHostWorkRbDesc::BthRethImmDt(data) => {
                assert_eq!(data.bth.dqpn, dqpn);
                assert_eq!(data.bth.opcode, RdmaOpcode::RdmaWriteFirst);
            }
            _ => panic!("unexpected descriptor"),
        }
        let q2 = device.get_to_host_descriptor_queue().pop().unwrap();
        match q2 {
            ToHostWorkRbDesc::BthRethImmDt(data) => {
                assert_eq!(data.bth.dqpn, dqpn);
                assert_eq!(data.bth.opcode, RdmaOpcode::RdmaWriteLast);
                assert_eq!(data.reth.va, dest_addr + 512);
                assert_eq!(u32::from_be_bytes(data.reth.rkey), mr1_rkey);
            }
            _ => panic!("unexpected descriptor"),
        }
        assert!(device.get_to_host_descriptor_queue().is_empty());
        assert_eq!(
            dest_buffer[dest_offset..dest_offset + 1024],
            src_buf[..send_length as usize]
        );

        // recover the dest buffer
        for i in dest_buffer.iter_mut() {
            *i = 0;
        }
    }

    // test a unalign sending
    // still 2ptmu, but offset = 5
    {
        let send_length = 2 * pmtu;
        let testing_dest_addr_offset: usize = 5;
        let desc = ToCardWorkRbDesc::Request(ToCardWorkRbDescRequest {
            common_header: ToCardWorkRbDescCommonHeader {
                valid: true,
                opcode: ToCardWorkRbDescOpcode::RdmaWrite,
                is_last: true,
                is_first: true,
                extra_segment_cnt: 0,
                is_success_or_need_signal_cplt: false,
                total_len: send_length as u32,
            },
            raddr: dest_addr + testing_dest_addr_offset as u64,
            rkey: mr1_rkey.to_be_bytes(),
            dqp_ip: Ipv4Addr::new(127, 0, 0, 1),
            pmtu: Pmtu::Mtu512,
            flags: 0,
            qp_type: QpType::Rc,
            sge_cnt: 0,
            psn: 1234,
            mac_addr: [0u8; 6],
            dqpn,
            imm: [0u8; 4],
            sgl: ScatterGatherList {
                data: [ScatterGatherElement {
                    laddr: src_addr,
                    len: 1024,
                    lkey: 0_u32.to_be_bytes(),
                }; 4],
                len: 1,
            },
        });

        device.send(desc).unwrap();
        // sync the sending packet
        sleep(Duration::from_millis(time_to_wait_in_mill));
        let q1 = device.get_to_host_descriptor_queue().pop().unwrap();
        match q1 {
            ToHostWorkRbDesc::BthRethImmDt(data) => {
                assert_eq!(data.bth.dqpn, dqpn);
                assert_eq!(data.bth.opcode, RdmaOpcode::RdmaWriteFirst);
                assert_eq!(data.reth.va, dest_addr + testing_dest_addr_offset as u64);
            }
            _ => panic!("unexpected descriptor"),
        }
        let q2 = device.get_to_host_descriptor_queue().pop().unwrap();
        match q2 {
            ToHostWorkRbDesc::BthRethImmDt(data) => {
                assert_eq!(data.bth.dqpn, dqpn);
                assert_eq!(data.bth.opcode, RdmaOpcode::RdmaWriteMiddle);
                assert_eq!(data.reth.va, dest_addr + pmtu);
            }
            _ => panic!("unexpected descriptor"),
        }
        let q3 = device.get_to_host_descriptor_queue().pop().unwrap();
        match q3 {
            ToHostWorkRbDesc::BthRethImmDt(data) => {
                assert_eq!(data.bth.dqpn, dqpn);
                assert_eq!(data.bth.opcode, RdmaOpcode::RdmaWriteLast);
                assert_eq!(data.reth.va, dest_addr + 2 * pmtu);
            }
            _ => panic!("unexpected descriptor"),
        }
        assert!(device.get_to_host_descriptor_queue().is_empty());
        assert_eq!(
            dest_buffer[dest_offset + testing_dest_addr_offset
                ..dest_offset + testing_dest_addr_offset + send_length as usize],
            src_buf[..send_length as usize]
        );

        // recover the dest buffer
        for i in dest_buffer.iter_mut() {
            *i = 0;
        }
    }

    // test read request
    {
        let send_length = 2 * pmtu;
        // let testing_dest_addr_offset: usize = 5;
        let desc = ToCardWorkRbDesc::Request(ToCardWorkRbDescRequest {
            common_header: ToCardWorkRbDescCommonHeader {
                valid: true,
                opcode: ToCardWorkRbDescOpcode::RdmaRead,
                is_last: true,
                is_first: true,
                extra_segment_cnt: 0,
                is_success_or_need_signal_cplt: false,
                total_len: send_length as u32,
            },
            raddr: src_addr,
            rkey: mr2_rkey.to_be_bytes(),
            dqp_ip: Ipv4Addr::new(127, 0, 0, 1),
            pmtu: Pmtu::Mtu512,
            flags: 0,
            qp_type: QpType::Rc,
            sge_cnt: 0,
            psn: 1234,
            mac_addr: [0u8; 6],
            dqpn,
            imm: [0u8; 4],
            sgl: ScatterGatherList {
                data: [ScatterGatherElement {
                    laddr: dest_addr,
                    len: 1024,
                    lkey: mr1_rkey.to_be_bytes(),
                }; 4],
                len: 1,
            },
        });

        device.send(desc).unwrap();
        // sync the sending packet
        sleep(Duration::from_millis(time_to_wait_in_mill));
        let q1 = device.get_to_host_descriptor_queue().pop().unwrap();
        match q1 {
            ToHostWorkRbDesc::SecondaryReth(data) => {
                assert_eq!(data.sec_reth.secondary_va, dest_addr);
                assert_eq!(data.sec_reth.secondary_rkey, mr1_rkey.to_be_bytes());
            }
            _ => panic!("unexpected descriptor"),
        }
        assert!(device.get_to_host_descriptor_queue().is_empty());

        let desc = ToCardWorkRbDesc::Request(ToCardWorkRbDescRequest {
            common_header: ToCardWorkRbDescCommonHeader {
                valid: true,
                opcode: ToCardWorkRbDescOpcode::RdmaReadResp,
                is_last: true,
                is_first: true,
                extra_segment_cnt: 0,
                is_success_or_need_signal_cplt: false,
                total_len: send_length as u32,
            },
            raddr: dest_addr,
            rkey: mr1_rkey.to_be_bytes(),
            dqp_ip: Ipv4Addr::new(127, 0, 0, 1),
            pmtu: Pmtu::Mtu512,
            flags: 0,
            qp_type: QpType::Rc,
            sge_cnt: 0,
            psn: 1234,
            mac_addr: [0u8; 6],
            dqpn,
            imm: [0u8; 4],
            sgl: ScatterGatherList {
                data: [ScatterGatherElement {
                    laddr: src_addr,
                    len: 1024,
                    lkey: 0_u32.to_be_bytes(),
                }; 4],
                len: 1,
            },
        });
        device.send(desc).unwrap();
        // sync the sending packet
        sleep(Duration::from_millis(time_to_wait_in_mill));
        let len = device.get_to_host_descriptor_queue().len();
        assert_eq!(len, 2);
        assert_eq!(
            dest_buffer[dest_offset..dest_offset + send_length as usize],
            src_buf[src_offset..src_offset + send_length as usize]
        );
    }
}

#[test]
#[serial]
fn test_software_device() {
    let device = SoftwareDevice::init().unwrap();
    let mr1_rkey = 1234;
    let mr2_rkey = 4321;
    let dqpn = 5;
    let pmtu = 512;
    // create a mr
    let src_buf = [1u8; 4096];
    let src_addr = src_buf.as_ptr() as u64;
    let src_offset = (src_addr - src_buf.as_ptr() as u64) as usize;
    let mut dest_buffer = [0u8; 4096];
    let dest_addr = (dest_buffer.as_ptr() as u64 + pmtu - 1) & !(pmtu - 1);
    let dest_offset = (dest_addr - dest_buffer.as_ptr() as u64) as usize;
    let time_to_wait_in_mill = 100;
    {
        let ctrl_rb = device.to_card_ctrl_rb();
        // create mr for write
        let mr_desc = ToCardCtrlRbDesc::UpdateMrTable(ToCardCtrlRbDescUpdateMrTable {
            common_header: CtrlRbDescCommonHeader {
                valid: true,
                opcode: CtrlRbDescOpcode::UpdateMrTable,
                extra_segment_cnt: 0,
                is_success_or_need_signal_cplt: false,
                user_data: [0; 4],
            },
            base_va: dest_addr,
            mr_length: 2048,
            mr_key: mr1_rkey,
            pd_handler: 0,
            acc_flags: (MemAccessTypeFlag::IbvAccessRemoteWrite
                | MemAccessTypeFlag::IbvAccessRemoteRead)
                .bits(),
            pgt_offset: 0,
        });
        ctrl_rb.push(mr_desc).unwrap();

        let mr_desc = ToCardCtrlRbDesc::UpdateMrTable(ToCardCtrlRbDescUpdateMrTable {
            common_header: CtrlRbDescCommonHeader {
                valid: true,
                opcode: CtrlRbDescOpcode::UpdateMrTable,
                extra_segment_cnt: 0,
                is_success_or_need_signal_cplt: false,
                user_data: [0; 4],
            },
            base_va: src_addr,
            mr_length: 2048,
            mr_key: mr2_rkey,
            pd_handler: 0,
            acc_flags: (MemAccessTypeFlag::IbvAccessRemoteWrite
                | MemAccessTypeFlag::IbvAccessRemoteRead)
                .bits(),
            pgt_offset: 0,
        });
        ctrl_rb.push(mr_desc).unwrap();

        // create qp
        let qp_desc = ToCardCtrlRbDesc::QpManagement(ToCardCtrlRbDescQpManagement {
            common_header: CtrlRbDescCommonHeader {
                valid: true,
                opcode: CtrlRbDescOpcode::UpdateMrTable,
                extra_segment_cnt: 0,
                is_success_or_need_signal_cplt: false,
                user_data: [0; 4],
            },
            is_valid: true,
            is_error: false,
            qpn: dqpn,
            pd_handler: 1,
            qp_type: QpType::Rc,
            rq_access_flags: MemAccessTypeFlag::IbvAccessRemoteWrite.bits(),
            pmtu: Pmtu::Mtu512,
        });
        ctrl_rb.push(qp_desc).unwrap();
    }

    // test a align sending
    {
        let send_length = 2 * pmtu;
        let desc = ToCardWorkRbDesc::Request(ToCardWorkRbDescRequest {
            common_header: ToCardWorkRbDescCommonHeader {
                valid: true,
                opcode: ToCardWorkRbDescOpcode::RdmaWrite,
                is_last: true,
                is_first: true,
                extra_segment_cnt: 0,
                is_success_or_need_signal_cplt: false,
                total_len: send_length as u32,
            },
            raddr: dest_addr,
            rkey: mr1_rkey.to_be_bytes(),
            dqp_ip: Ipv4Addr::new(127, 0, 0, 1),
            pmtu: Pmtu::Mtu512,
            flags: 0,
            qp_type: QpType::Rc,
            sge_cnt: 0,
            psn: 1234,
            mac_addr: [0u8; 6],
            dqpn,
            imm: [0u8; 4],
            sgl: ScatterGatherList {
                data: [ScatterGatherElement {
                    laddr: src_addr,
                    len: 1024,
                    lkey: 0_u32.to_be_bytes(),
                }; 4],
                len: 1,
            },
        });
        let to_card_work_rb = device.to_card_work_rb();
        to_card_work_rb.push(desc).unwrap();
        let to_host_work_rb = device.to_host_work_rb();
        // sync the sending packet
        sleep(Duration::from_millis(time_to_wait_in_mill));
        let q1 = to_host_work_rb.pop().unwrap();
        match q1 {
            ToHostWorkRbDesc::BthRethImmDt(data) => {
                assert_eq!(data.bth.dqpn, dqpn);
                assert_eq!(data.bth.opcode, RdmaOpcode::RdmaWriteFirst);
            }
            _ => panic!("unexpected descriptor"),
        }
        let q2 = to_host_work_rb.pop().unwrap();
        match q2 {
            ToHostWorkRbDesc::BthRethImmDt(data) => {
                assert_eq!(data.bth.dqpn, dqpn);
                assert_eq!(data.bth.opcode, RdmaOpcode::RdmaWriteLast);
                assert_eq!(data.reth.va, dest_addr + 512);
                assert_eq!(u32::from_be_bytes(data.reth.rkey), mr1_rkey);
            }
            _ => panic!("unexpected descriptor"),
        }
        // assert!(device.get_to_host_descriptor_queue().is_empty());
        assert_eq!(
            dest_buffer[dest_offset..dest_offset + 1024],
            src_buf[..send_length as usize]
        );

        // recover the dest buffer
        for i in dest_buffer.iter_mut() {
            *i = 0;
        }
    }

    // test a unalign sending
    // still 2ptmu, but offset = 5
    {
        let to_card_work_rb = device.to_card_work_rb();
        let to_host_work_rb = device.to_host_work_rb();
        let send_length = 2 * pmtu;
        let testing_dest_addr_offset: usize = 5;
        let desc = ToCardWorkRbDesc::Request(ToCardWorkRbDescRequest {
            common_header: ToCardWorkRbDescCommonHeader {
                valid: true,
                opcode: ToCardWorkRbDescOpcode::RdmaWrite,
                is_last: true,
                is_first: true,
                extra_segment_cnt: 0,
                is_success_or_need_signal_cplt: false,
                total_len: send_length as u32,
            },
            raddr: dest_addr + testing_dest_addr_offset as u64,
            rkey: mr1_rkey.to_be_bytes(),
            dqp_ip: Ipv4Addr::new(127, 0, 0, 1),
            pmtu: Pmtu::Mtu512,
            flags: 0,
            qp_type: QpType::Rc,
            sge_cnt: 0,
            psn: 1234,
            mac_addr: [0u8; 6],
            dqpn,
            imm: [0u8; 4],
            sgl: ScatterGatherList {
                data: [ScatterGatherElement {
                    laddr: src_addr,
                    len: 1024,
                    lkey: 0_u32.to_be_bytes(),
                }; 4],
                len: 1,
            },
        });

        to_card_work_rb.push(desc).unwrap();
        // sync the sending packet
        sleep(Duration::from_millis(time_to_wait_in_mill));
        let q1 = to_host_work_rb.pop().unwrap();
        match q1 {
            ToHostWorkRbDesc::BthRethImmDt(data) => {
                assert_eq!(data.bth.dqpn, dqpn);
                assert_eq!(data.bth.opcode, RdmaOpcode::RdmaWriteFirst);
                assert_eq!(data.reth.va, dest_addr + testing_dest_addr_offset as u64);
            }
            _ => panic!("unexpected descriptor"),
        }
        let q2 = to_host_work_rb.pop().unwrap();
        match q2 {
            ToHostWorkRbDesc::BthRethImmDt(data) => {
                assert_eq!(data.bth.dqpn, dqpn);
                assert_eq!(data.bth.opcode, RdmaOpcode::RdmaWriteMiddle);
                assert_eq!(data.reth.va, dest_addr + pmtu);
            }
            _ => panic!("unexpected descriptor"),
        }
        let q3 = to_host_work_rb.pop().unwrap();
        match q3 {
            ToHostWorkRbDesc::BthRethImmDt(data) => {
                assert_eq!(data.bth.dqpn, dqpn);
                assert_eq!(data.bth.opcode, RdmaOpcode::RdmaWriteLast);
                assert_eq!(data.reth.va, dest_addr + 2 * pmtu);
            }
            _ => panic!("unexpected descriptor"),
        }
        // assert!(device.get_to_host_descriptor_queue().is_empty());
        assert_eq!(
            dest_buffer[dest_offset + testing_dest_addr_offset
                ..dest_offset + testing_dest_addr_offset + send_length as usize],
            src_buf[..send_length as usize]
        );

        // recover the dest buffer
        for i in dest_buffer.iter_mut() {
            *i = 0;
        }
    }

    // test read request
    {
        let to_card_work_rb = device.to_card_work_rb();
        let to_host_work_rb = device.to_host_work_rb();
        let send_length = 2 * pmtu;
        // let testing_dest_addr_offset: usize = 5;
        let desc = ToCardWorkRbDesc::Request(ToCardWorkRbDescRequest {
            common_header: ToCardWorkRbDescCommonHeader {
                valid: true,
                opcode: ToCardWorkRbDescOpcode::RdmaRead,
                is_last: true,
                is_first: true,
                extra_segment_cnt: 0,
                is_success_or_need_signal_cplt: false,
                total_len: send_length as u32,
            },
            raddr: src_addr,
            rkey: mr2_rkey.to_be_bytes(),
            dqp_ip: Ipv4Addr::new(127, 0, 0, 1),
            pmtu: Pmtu::Mtu512,
            flags: 0,
            qp_type: QpType::Rc,
            sge_cnt: 0,
            psn: 1234,
            mac_addr: [0u8; 6],
            dqpn,
            imm: [0u8; 4],
            sgl: ScatterGatherList {
                data: [ScatterGatherElement {
                    laddr: dest_addr,
                    len: 1024,
                    lkey: mr1_rkey.to_be_bytes(),
                }; 4],
                len: 1,
            },
        });

        to_card_work_rb.push(desc).unwrap();
        // sync the sending packet
        sleep(Duration::from_millis(time_to_wait_in_mill));
        let q1 = to_host_work_rb.pop().unwrap();
        match q1 {
            ToHostWorkRbDesc::SecondaryReth(data) => {
                assert_eq!(data.sec_reth.secondary_va, dest_addr);
                assert_eq!(data.sec_reth.secondary_rkey, mr1_rkey.to_be_bytes());
            }
            _ => panic!("unexpected descriptor"),
        }
        // assert!(device.get_to_host_descriptor_queue().is_empty());

        let desc = ToCardWorkRbDesc::Request(ToCardWorkRbDescRequest {
            common_header: ToCardWorkRbDescCommonHeader {
                valid: true,
                opcode: ToCardWorkRbDescOpcode::RdmaReadResp,
                is_last: true,
                is_first: true,
                extra_segment_cnt: 0,
                is_success_or_need_signal_cplt: false,
                total_len: send_length as u32,
            },
            raddr: dest_addr,
            rkey: mr1_rkey.to_be_bytes(),
            dqp_ip: Ipv4Addr::new(127, 0, 0, 1),
            pmtu: Pmtu::Mtu512,
            flags: 0,
            qp_type: QpType::Rc,
            sge_cnt: 0,
            psn: 1234,
            mac_addr: [0u8; 6],
            dqpn,
            imm: [0u8; 4],
            sgl: ScatterGatherList {
                data: [ScatterGatherElement {
                    laddr: src_addr,
                    len: 1024,
                    lkey: 0_u32.to_be_bytes(),
                }; 4],
                len: 1,
            },
        });
        to_card_work_rb.push(desc).unwrap();
        // sync the sending packet
        sleep(Duration::from_millis(time_to_wait_in_mill));
        // let len = device.get_to_host_descriptor_queue().len();
        // assert_eq!(len, 2);
        assert_eq!(
            dest_buffer[dest_offset..dest_offset + send_length as usize],
            src_buf[src_offset..src_offset + send_length as usize]
        );
    }
}
