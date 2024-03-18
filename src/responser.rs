use std::collections::HashMap;
use std::sync::RwLock;
use std::{net::Ipv4Addr, slice::from_raw_parts_mut, sync::Arc, thread::spawn};

use bitfield::bitfield;
use lockfree::queue::Queue;

use crate::qp::QpContext;
use crate::types::{Key, MemAccessTypeFlag, Msn, Psn, QpType, Qpn};
use crate::utils::calculate_packet_cnt;
use crate::Sge;
use crate::{
    device::{
        ToCardWorkRbDescBuilder, ToCardWorkRbDescCommon, ToHostWorkRbDescAethCode,
        ToHostWorkRbDescOpcode, ToHostWorkRbDescRead,
    },
    Error,
};
/// A interface that allows DescResponser to push the work descriptor to the device
pub trait WorkDescriptorSender: Send + Sync {
    fn send_work_desc(&self, desc_builder: ToCardWorkRbDescBuilder) -> Result<(), Error>;
}

/// Command about ACK and NACK
/// Typically, the message is sent by checker thread, which is responsible for checking the packet ordering.
pub(crate) struct RespAckCommand {
    pub(crate) dpqn: Qpn,
    pub(crate) msn: Msn,
    pub(crate) psn: Psn,
    pub(crate) last_retry_psn: Option<Psn>,
}

impl RespAckCommand {
    pub(crate) fn new_ack(dpqn: Qpn, msn: Msn, last_psn: Psn) -> Self {
        Self {
            dpqn,
            msn,
            psn: last_psn,
            last_retry_psn: None,
        }
    }

    pub(crate) fn new_nack(dpqn: Qpn, msn: Msn, psn: Psn, last_retry_psn: Psn) -> Self {
        Self {
            dpqn,
            msn,
            psn,
            last_retry_psn: Some(last_retry_psn),
        }
    }
}

/// Command about read response
pub(crate) struct RespReadRespCommand {
    pub(crate) desc: ToHostWorkRbDescRead,
}

/// The response command sent by other threads
///
/// Currently, it supports two types of response:
/// * Acknowledge(ack,nack)
/// * Read Response
#[allow(dead_code)]
pub(crate) enum RespCommand {
    Acknowledge(RespAckCommand), // Acknowledge or Negative Acknowledge
    ReadResponse(RespReadRespCommand),
}

/// A thread that is responsible for sending the response to the other side
pub(crate) struct DescResponser {
    _thread: std::thread::JoinHandle<()>,
}

impl DescResponser {
    pub fn new(
        device: Arc<dyn WorkDescriptorSender>,
        recving_queue: std::sync::mpsc::Receiver<RespCommand>,
        ack_buffers: AcknowledgeBuffer,
        qp_table: Arc<RwLock<HashMap<Qpn, QpContext>>>,
    ) -> Self {
        let _thread = spawn(|| Self::working_thread(device, recving_queue, ack_buffers, qp_table));
        Self { _thread }
    }

    fn working_thread(
        device: Arc<dyn WorkDescriptorSender>,
        recving_queue: std::sync::mpsc::Receiver<RespCommand>,
        ack_buffers: AcknowledgeBuffer,
        qp_table: Arc<RwLock<HashMap<Qpn, QpContext>>>,
    ) {
        loop {
            match recving_queue.recv() {
                Ok(RespCommand::Acknowledge(ack)) => {
                    // send ack to device
                    let ack_buf = ack_buffers.alloc().unwrap();
                    let src_ip = Ipv4Addr::LOCALHOST;
                    let (dst_ip, common) = match qp_table.read().unwrap().get(&ack.dpqn) {
                        Some(qp) => {
                            let dst_ip = qp.dqp_ip;
                            let common = ToCardWorkRbDescCommon {
                                total_len: ACKPACKET_SIZE as u32,
                                rkey: Key::default(),
                                raddr: 0,
                                dqp_ip: qp.dqp_ip,
                                dqpn: qp.qpn,
                                mac_addr: qp.mac_addr,
                                pmtu: qp.pmtu.clone(),
                                flags: MemAccessTypeFlag::IbvAccessNoFlags,
                                qp_type: QpType::RawPacket,
                                psn: Psn::default(),
                            };
                            (dst_ip, common)
                        }
                        None => {
                            eprintln!("Failed to get QP from QP table: {:?}", ack.dpqn);
                            continue;
                        }
                    };

                    let last_retry_psn = ack.last_retry_psn;
                    if let Err(e) = write_packet(
                        ack_buf,
                        src_ip,
                        dst_ip,
                        ack.dpqn,
                        ack.msn,
                        ack.psn,
                        last_retry_psn,
                    ) {
                        eprintln!("Failed to write ack/nack packet: {:?}", e);
                        continue;
                    }
                    let sge = ack_buffers.convert_buf_into_sge(&ack_buf, ACKPACKET_SIZE as u32);
                    let desc_builder = ToCardWorkRbDescBuilder::new_write()
                        .with_common(common)
                        .with_sge(sge);
                    if let Err(e) = device.send_work_desc(desc_builder) {
                        eprintln!("Failed to push ack/nack packet: {:?}", e);
                    }
                    ack_buffers.free(ack_buf);
                }
                Ok(RespCommand::ReadResponse(resp)) => {
                    // send read response to device
                    let dpqn = resp.desc.common.dqpn;
                    let common = match qp_table.read().unwrap().get(&dpqn) {
                        Some(qp) => {
                            let mut common = ToCardWorkRbDescCommon {
                                total_len: resp.desc.len,
                                rkey: resp.desc.rkey,
                                raddr: resp.desc.raddr,
                                dqp_ip: qp.dqp_ip,
                                dqpn: dpqn,
                                mac_addr: qp.mac_addr,
                                pmtu: qp.pmtu.clone(),
                                flags: MemAccessTypeFlag::IbvAccessNoFlags,
                                qp_type: qp.qp_type,
                                psn: Psn::default(),
                            };
                            let send_psn = &mut qp.inner.lock().unwrap().send_psn;
                            common.psn = *send_psn;
                            let packet_cnt = calculate_packet_cnt(
                                qp.pmtu.clone(),
                                resp.desc.raddr,
                                resp.desc.len,
                            );
                            *send_psn = send_psn.wrapping_add(packet_cnt);
                            common
                        }
                        None => {
                            eprintln!("Failed to get QP from QP table: {:?}", dpqn);
                            continue;
                        }
                    };

                    let sge = Sge {
                        addr: resp.desc.laddr,
                        len: resp.desc.len,
                        key: resp.desc.lkey,
                    };
                    let desc_builder = ToCardWorkRbDescBuilder::new_read_resp()
                        .with_common(common)
                        .with_sge(sge);
                    if let Err(e) = device.send_work_desc(desc_builder) {
                        eprintln!("Failed to push read response: {:?}", e);
                    }
                }
                Err(_) => {
                    // The only error is pipe broken, so just exit the thread
                    return;
                }
            }
        }
    }
}

type Slot = &'static mut [u8];

/// A structure to hold the acknowledge buffer
///
/// TODO: currently, it does not support the auto buffer recycling.
///
/// The element is `Option<Slot>` because the `Queue` need to initialize some nodes as Sentinel
/// while the reference can not be initialized as `None`.
pub(crate) struct AcknowledgeBuffer {
    free_list: Queue<Option<Slot>>,
    start_va: usize,
    length: usize,
    lkey: Key,
}

impl AcknowledgeBuffer {
    pub const ACKNOWLEDGE_BUFFER_SLOT_SIZE: usize = 64;
    /// Create a new acknowledge buffer
    pub fn new(start_va: usize, length: usize, lkey: Key) -> Self {
        assert!(length % Self::ACKNOWLEDGE_BUFFER_SLOT_SIZE == 0);
        let free_list = Queue::new();
        let mut va = start_va;
        let slots: usize = length / Self::ACKNOWLEDGE_BUFFER_SLOT_SIZE;

        for _ in 0..slots {
            // SAFETY: the buffer given by the user should be valid, can be safely converted to array
            let buf =
                unsafe { from_raw_parts_mut(va as *mut u8, Self::ACKNOWLEDGE_BUFFER_SLOT_SIZE) };
            free_list.push(Some(buf));
            va += Self::ACKNOWLEDGE_BUFFER_SLOT_SIZE;
        }
        Self {
            free_list,
            start_va,
            length,
            lkey,
        }
    }

    pub fn alloc(&self) -> Option<Slot> {
        // FIXME: currently, we just recycle all the buffer in the free list.
        let result = self.free_list.pop();
        match result {
            Some(Some(buf)) => Some(buf),
            Some(None) => None,
            None => {
                // The buffer is already freed, so we just try to allocate another buffer
                let mut va = self.start_va;
                let slots: usize = self.length / Self::ACKNOWLEDGE_BUFFER_SLOT_SIZE;
                for _ in 0..slots {
                    // SAFETY: the buffer given by the user should be valid, can be safely converted to array
                    let buf = unsafe {
                        from_raw_parts_mut(va as *mut u8, Self::ACKNOWLEDGE_BUFFER_SLOT_SIZE)
                    };
                    self.free_list.push(Some(buf));
                    va += Self::ACKNOWLEDGE_BUFFER_SLOT_SIZE;
                }
                self.free_list.pop().map(|x| x.unwrap())
            }
        }
    }

    pub fn free(&self, buf: Slot) {
        // check if the buffer is within the range
        let start = self.start_va as *const u8;
        let end = start.wrapping_add(self.length);
        let buf_start = buf.as_ptr();
        let buf_end = buf_start.wrapping_add(AcknowledgeBuffer::ACKNOWLEDGE_BUFFER_SLOT_SIZE);
        assert!(
            buf_start >= start && buf_end <= end && buf.len() == Self::ACKNOWLEDGE_BUFFER_SLOT_SIZE
        );
        self.free_list.push(Some(buf));
    }

    pub fn convert_buf_into_sge(&self, buf: &Slot, real_length: u32) -> Sge {
        Sge {
            addr: buf.as_ptr() as u64,
            len: real_length,
            key: self.lkey,
        }
    }
}

bitfield! {
    /// IPv4 layout
    struct Ipv4([u8]);
    u32;
    get_version_and_len,set_version_and_len: 7, 0;         // 8bits
    get_dscp_ecn,set_dscp_ecn: 15, 8;                      // 8bits
    get_total_length,set_total_length: 31, 16;             // 16bits
    get_identification,set_identification: 47, 32;         // 16bits
    get_fragment_offset,set_fragment_offset: 63, 48;       // 16bits
    get_ttl,set_ttl: 71, 64;                               // 8bits
    get_protocol,set_protocol: 79, 72;                     // 8bits
    get_checksum,set_checksum: 95, 80;                     // 16bits
    get_source,set_source: 127, 96;                        // 32bits
    get_destination,set_destination: 159, 128;             // 32bits
}

bitfield! {
    /// UDP layout
    struct Udp([u8]);
    u16;
    get_src_port,set_src_port: 15, 0;                      // 16bits
    get_dst_port,set_dst_port: 31, 16;                     // 16bits
    get_length,set_length: 47, 32;                         // 16bits
    get_checksum,set_checksum: 63, 48;                     // 16bits
}

bitfield! {
    /// BTH layout
    struct Bth([u8]);
    u32;
    get_opcode,set_opcode: 7, 0;         // 8bits
    _padding_0,_ : 9, 8;                 // 2bits
    get_pad_count,set_pad_count: 11, 10; // 2bits
    _padding_1,_ : 15, 12;               // 4bits
    get_pkey,set_pkey: 31, 16;           // 16bits
    _,set_ecn_and_resv6: 39, 32;         // 8bits
    get_dqpn,set_dqpn: 63, 40;           // 24bits
    _padding_2,_ : 71, 64;               // 8bits
    get_psn,set_psn: 95, 72;             // 24bits
}

bitfield! {
    /// Aeth layout
    struct Aeth([u8]);
    u32;
    _padding_0,_ : 0;                     // 1bits
    get_aeth_code,set_aeth_code: 2, 1;    // 2bits
    get_aeth_value,set_aeth_value: 7, 3;  // 5bits
    get_msn,set_msn: 31, 8;               // 24bits
}

bitfield! {
    /// Nak Retry Eth layout
    struct NReth([u8]);
    u32;
    get_last_retry_psn,set_last_retry_psn: 23, 0; // 24bits
    _padding_0,_: 31, 24;                         // 8its
}

/// Write the IP header and UDP header
fn write_packet(
    buf: &mut [u8],
    src_addr: Ipv4Addr,
    dst_addr: Ipv4Addr,
    dpqn: Qpn,
    msn: Msn,
    psn: Psn,
    last_retry_psn: Option<Psn>,
) -> Result<(), Error> {
    // write a ip header
    let mut ip_header = Ipv4(buf);
    ip_header.set_version_and_len(IP_DEFAULT_VERSION_AND_LEN as u32);
    ip_header.set_dscp_ecn(0);
    ip_header.set_total_length(ACKPACKET_SIZE.to_be() as u32);
    ip_header.set_identification(0);
    ip_header.set_fragment_offset(0);
    ip_header.set_ttl(IP_DEFAULT_TTL as u32);
    ip_header.set_protocol(IP_DEFAULT_PROTOCOL as u32);
    let src_addr: u32 = src_addr.into();
    ip_header.set_source(src_addr.to_be());
    let dst_addr: u32 = dst_addr.into();
    ip_header.set_destination(dst_addr.to_be());
    // Set the checksum to 0, and calculate the checksum later
    ip_header.set_checksum(0);
    let checksum = calculate_ipv4_checksum(ip_header.0).to_be();
    ip_header.set_checksum(checksum.into());
    let buf = ip_header.0;

    let mut udp_header = Udp(&mut buf[IPV4_HEADER_SIZE..]);
    udp_header.set_src_port(RDMA_DEFAULT_PORT.to_be());
    udp_header.set_dst_port(RDMA_DEFAULT_PORT.to_be());
    udp_header.set_length((ACKPACKET_WITHOUT_IPV4_HEADER_SIZE as u16).to_be());
    // It might redundant to calculate checksum, as the ICRC will calculate the another checksum
    udp_header.set_checksum(0);

    let mut bth_header = Bth(&mut buf[IPV4_HEADER_SIZE + UDP_HEADER_SIZE..]);
    bth_header.set_opcode(ToHostWorkRbDescOpcode::Acknowledge as u32);
    bth_header.set_pad_count(0);
    bth_header.set_pkey(0);
    bth_header.set_ecn_and_resv6(0);

    bth_header.set_dqpn(dpqn.into_be());
    bth_header.set_psn(psn.into_be());

    let is_nak = last_retry_psn.is_some();

    let mut aeth_header = Aeth(&mut buf[IPV4_HEADER_SIZE + UDP_HEADER_SIZE + BTH_HEADER_SIZE..]);
    if is_nak {
        aeth_header.set_aeth_code(ToHostWorkRbDescAethCode::Nak as u32);
    } else {
        aeth_header.set_aeth_code(ToHostWorkRbDescAethCode::Ack as u32);
    }
    aeth_header.set_aeth_value(0);
    aeth_header.set_msn(msn.into_be());

    let mut nreth_header =
        NReth(&mut buf[IPV4_HEADER_SIZE + UDP_HEADER_SIZE + BTH_HEADER_SIZE + AETH_HEADER_SIZE..]);
    if is_nak {
        let last_retry_psn = last_retry_psn.unwrap().into_be();
        nreth_header.set_last_retry_psn(last_retry_psn);
    } else {
        nreth_header.set_last_retry_psn(0);
    }
    // calculate the ICRC
    calculate_icrc(buf)?;
    Ok(())
}

const IPV4_HEADER_SIZE: usize = 20;
const UDP_HEADER_SIZE: usize = 8;
const BTH_HEADER_SIZE: usize = 12;
const IPV4_UDP_BTH_HEADER_SIZE: usize = IPV4_HEADER_SIZE + UDP_HEADER_SIZE + BTH_HEADER_SIZE;
const AETH_HEADER_SIZE: usize = 4;
const NRETH_HEADER_SIZE: usize = 4;
const ICRCSIZE: usize = 4;
const ACKPACKET_SIZE: usize = IPV4_HEADER_SIZE
    + UDP_HEADER_SIZE
    + BTH_HEADER_SIZE
    + AETH_HEADER_SIZE
    + NRETH_HEADER_SIZE
    + ICRCSIZE;
const ACKPACKET_WITHOUT_IPV4_HEADER_SIZE: usize =
    UDP_HEADER_SIZE + BTH_HEADER_SIZE + AETH_HEADER_SIZE + NRETH_HEADER_SIZE + ICRCSIZE;

const IP_DEFAULT_VERSION_AND_LEN: u8 = 0x45;
const IP_DEFAULT_TTL: u8 = 64;
const IP_DEFAULT_PROTOCOL: u8 = 17;
const RDMA_DEFAULT_PORT: u16 = 4791;

/// Calculate the RDMA packet ICRC.
///
/// the `data` passing in should include the space for the ICRC(4 bytes).
fn calculate_icrc(data: &mut [u8]) -> Result<(), Error> {
    let mut hasher = crc32fast::Hasher::new();
    let prefix = [0xffu8; 8];
    let mut buf = [0; IPV4_UDP_BTH_HEADER_SIZE];
    hasher.update(&prefix);

    buf.copy_from_slice(data[..IPV4_UDP_BTH_HEADER_SIZE].as_ref());
    let mut ip_header = Ipv4(&mut buf);
    ip_header.set_dscp_ecn(0xff);
    ip_header.set_ttl(0xff);
    ip_header.set_checksum(0xffff);

    let mut udp_header = Udp(&mut buf[IPV4_HEADER_SIZE..]);
    udp_header.set_checksum(0xffff);

    let mut bth_header = Bth(&mut buf[IPV4_HEADER_SIZE + UDP_HEADER_SIZE..]);
    bth_header.set_ecn_and_resv6(0xff);

    hasher.update(&buf);
    // the rest of header and payload
    hasher.update(&data[IPV4_UDP_BTH_HEADER_SIZE..data.len() - 4]);
    let icrc = hasher.finalize();
    let len = data.len();
    data[len - 4..].copy_from_slice(&icrc.to_be_bytes());
    Ok(())
}

/// Calculate the checksum of the IPv4 header
///
/// The `header` should be a valid IPv4 header, and the checksum field is set to 0.
fn calculate_ipv4_checksum(header: &[u8]) -> u16 {
    let mut sum = 0u32;

    for i in (0..IPV4_HEADER_SIZE).step_by(2) {
        let word = if i + 1 < header.len() {
            ((header[i] as u16) << 8) | header[i + 1] as u16
        } else {
            (header[i] as u16) << 8
        };
        sum += word as u32;
    }

    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    !sum as u16
}

#[cfg(test)]
mod tests {
    use std::{sync::Mutex, thread::sleep};

    use crate::{
        device::{ToCardWorkRbDescBuilder, ToHostWorkRbDescCommon, ToHostWorkRbDescRead},
        qp::QpContext,
        responser::{calculate_ipv4_checksum, ACKPACKET_SIZE},
        types::{Key, MemAccessTypeFlag, Msn, Pmtu, Psn, Qpn},
    };

    #[test]
    fn test_calculate_ipv4_checksum() {
        // capture from a real packet
        let ref_header: [u8; 20] = [
            0x45, 0x00, 0x00, 0x34, 0xb4, 0xef, 0x40, 0x00, 0x25, 0x06, 0x00, 0x00, 0x14, 0x59,
            0xed, 0x08, 0xac, 0x1b, 0xe8, 0xda,
        ];
        let expected_checksum: u16 = u16::from_be_bytes([0x0a, 0x7d]);
        let checksum = calculate_ipv4_checksum(&ref_header);
        assert_eq!(checksum, expected_checksum);
        let ref_header = [
            0x45, 0x00, 0x02, 0x0c, 0x3f, 0x3b, 0x40, 0x00, 0x29, 0x06, 0x00, 0x00, 0x8c, 0x52,
            0x72, 0x15, 0xac, 0x1b, 0xe8, 0xda,
        ];
        let expected_checksum: u16 = u16::from_be_bytes([0x7d, 0x53]);
        let checksum = calculate_ipv4_checksum(&ref_header);
        assert_eq!(checksum, expected_checksum);
    }

    const BUFFER_SIZE: usize = 1024 * super::AcknowledgeBuffer::ACKNOWLEDGE_BUFFER_SLOT_SIZE;
    #[test]
    fn test_desc_responser() {
        let (sender, receiver) = std::sync::mpsc::channel();
        let buffer = Box::new([0u8; BUFFER_SIZE]);
        let buffer = Box::leak(buffer);
        let ack_buffers =
            super::AcknowledgeBuffer::new(buffer.as_ptr() as usize, BUFFER_SIZE, Key::new(0x1000));
        struct Dummy(Mutex<Vec<ToCardWorkRbDescBuilder>>);
        impl super::WorkDescriptorSender for Dummy {
            fn send_work_desc(
                &self,
                desc_builder: ToCardWorkRbDescBuilder,
            ) -> Result<(), crate::Error> {
                self.0.lock().unwrap().push(desc_builder);
                Ok(())
            }
        }
        let dummy = std::sync::Arc::new(Dummy(Mutex::new(Vec::new())));
        let qp_table =
            std::sync::Arc::new(std::sync::RwLock::new(std::collections::HashMap::new()));
        qp_table.write().unwrap().insert(
            Qpn::new(3),
            QpContext {
                handle: 0,
                pd: crate::Pd { handle: 0 },
                qpn: Qpn::new(3),
                qp_type: crate::types::QpType::Rc,
                rq_acc_flags: MemAccessTypeFlag::IbvAccessNoFlags,
                pmtu: Pmtu::Mtu4096,
                dqp_ip: std::net::Ipv4Addr::LOCALHOST,
                mac_addr: [0u8; 6],
                inner: std::sync::Mutex::new(crate::qp::QpInner {
                    send_psn: Psn::default(),
                    recv_psn: Psn::default(),
                }),
            },
        );
        let _ = super::DescResponser::new(dummy.clone(), receiver, ack_buffers, qp_table);
        sender
            .send(super::RespCommand::Acknowledge(super::RespAckCommand {
                dpqn: Qpn::new(3),
                msn: Msn::new(0),
                psn: Psn::new(0),
                last_retry_psn: None,
            }))
            .unwrap();
        sender
            .send(super::RespCommand::Acknowledge(super::RespAckCommand {
                dpqn: Qpn::new(3),
                msn: Msn::new(0),
                psn: Psn::new(0),
                last_retry_psn: Option::Some(Psn::new(12)),
            }))
            .unwrap();
        sender
            .send(super::RespCommand::ReadResponse(
                super::RespReadRespCommand {
                    desc: ToHostWorkRbDescRead {
                        common: ToHostWorkRbDescCommon {
                            status: crate::device::ToHostWorkRbDescStatus::Normal,
                            trans: crate::device::ToHostWorkRbDescTransType::Rc,
                            dqpn: Qpn::new(3),
                            pad_cnt: 0,
                        },
                        len: 10,
                        laddr: 10,
                        lkey: Key::new(10),
                        raddr: 0,
                        rkey: Key::new(10),
                    },
                },
            ))
            .unwrap();
        drop(sender);

        // check
        sleep(std::time::Duration::from_millis(10));
        let mut v = dummy.0.lock().unwrap();
        assert_eq!(v.len(), 3);
        let builder = v.pop().unwrap();
        let desc = builder.build().unwrap();
        match desc {
            crate::device::ToCardWorkRbDesc::ReadResp(desc) => {
                assert_eq!(desc.common.dqpn.get(), 3);
                assert_eq!(desc.common.total_len, 10_u32);
                assert_eq!(desc.common.rkey.get(), 10);
                assert_eq!(desc.common.raddr, 0);
                assert_eq!(desc.common.dqp_ip, std::net::Ipv4Addr::LOCALHOST);
                assert_eq!(desc.common.mac_addr, [0u8; 6]);
                assert!(matches!(desc.common.pmtu, Pmtu::Mtu4096));
                assert_eq!(desc.common.flags.bits(), 0);
                assert!(matches!(desc.common.qp_type, crate::types::QpType::Rc));
                assert_eq!(desc.common.psn.get(), 0);
                assert_eq!(desc.sge0.len, 10_u32);
                assert_eq!(desc.sge0.key.get(), 10);
            }
            _ => {
                panic!("Unexpected desc type");
            }
        }
        let builder = v.pop().unwrap();
        // NACK
        let desc = builder.build().unwrap();
        match desc {
            crate::device::ToCardWorkRbDesc::Write(desc) => {
                assert_eq!(desc.common.dqpn.get(), 3);
                assert_eq!(desc.common.total_len, ACKPACKET_SIZE as u32);
                assert_eq!(desc.common.rkey.get(), 0);
                assert_eq!(desc.common.raddr, 0);
                assert_eq!(desc.common.dqp_ip, std::net::Ipv4Addr::LOCALHOST);
                assert_eq!(desc.common.mac_addr, [0u8; 6]);
                assert!(matches!(desc.common.pmtu, Pmtu::Mtu4096));
                assert_eq!(desc.common.flags.bits(), 0);
                assert!(matches!(
                    desc.common.qp_type,
                    crate::types::QpType::RawPacket
                ));
                assert_eq!(desc.common.psn.get(), 0);
                assert_eq!(desc.sge0.len, ACKPACKET_SIZE as u32);
                assert_eq!(desc.sge0.key.get(), 0x1000);
            }
            _ => {
                panic!("Unexpected desc type");
            }
        }

        // ACK
        let builder = v.pop().unwrap();
        let desc = builder.build().unwrap();
        match desc {
            crate::device::ToCardWorkRbDesc::Write(desc) => {
                assert_eq!(desc.common.dqpn.get(), 3);
                assert_eq!(desc.common.total_len, ACKPACKET_SIZE as u32);
                assert_eq!(desc.common.rkey.get(), 0);
                assert_eq!(desc.common.raddr, 0);
                assert_eq!(desc.common.dqp_ip, std::net::Ipv4Addr::LOCALHOST);
                assert_eq!(desc.common.mac_addr, [0u8; 6]);
                assert!(matches!(desc.common.pmtu, Pmtu::Mtu4096));
                assert_eq!(desc.common.flags.bits(), 0);
                assert!(matches!(
                    desc.common.qp_type,
                    crate::types::QpType::RawPacket
                ));
                assert_eq!(desc.common.psn.get(), 0);
                assert_eq!(desc.sge0.len, ACKPACKET_SIZE as u32);
                assert_eq!(desc.sge0.key.get(), 0x1000);
            }
            _ => {
                panic!("Unexpected desc type");
            }
        }
    }

    #[test]
    fn test_acknowledge_buffer() {
        let mem = Box::leak(Box::new(
            [0u8; 1024 * super::AcknowledgeBuffer::ACKNOWLEDGE_BUFFER_SLOT_SIZE],
        ));
        let base_va = mem.as_ptr() as usize;
        let buffer = super::AcknowledgeBuffer::new(base_va, 1024 * 64, Key::new(0x1000));
        for i in 0..1024 {
            let buf = buffer.alloc().unwrap();
            assert_eq!(
                buf.as_ptr() as usize,
                mem.as_ptr() as usize + i * super::AcknowledgeBuffer::ACKNOWLEDGE_BUFFER_SLOT_SIZE
            );
        }
        // Now the buffer is full, it recycles the buffer
        for i in 0..1024 {
            let buf = buffer.alloc().unwrap();
            assert_eq!(buf.as_ptr() as usize, mem.as_ptr() as usize + i * 64);
        }
    }
}
