use std::{
    mem::{size_of, size_of_val},
    net::Ipv4Addr,
};

use thiserror::Error;

use super::{
    packet::{
        CommonPacketHeader, IpUdpHeaders, Ipv4Header, PacketError, RdmaAcknowledgeHeader,
        RdmaPacketHeader, RdmaReadRequestHeader, RdmaReadResponseFirstHeader,
        RdmaReadResponseLastHeader, RdmaReadResponseMiddleHeader, RdmaReadResponseOnlyHeader,
        RdmaWriteFirstHeader, RdmaWriteLastHeader, RdmaWriteLastWithImmediateHeader,
        RdmaWriteMiddleHeader, RdmaWriteOnlyHeader, RdmaWriteOnlyWithImmediateHeader, BTH,
        ICRC_SIZE,
    },
    types::{PayloadInfo, RdmaMessage},
};
use crate::device::RdmaOpcode;

pub(crate) struct PacketProcessor;

impl PacketProcessor {
    pub fn to_rdma_message(&self, buf: &[u8]) -> Result<RdmaMessage, PacketError> {
        let opcode = RdmaOpcode::try_from(BTH::from_bytes(buf).get_opcode());
        match opcode {
            Ok(RdmaOpcode::RdmaWriteFirst) => {
                let header = RdmaWriteFirstHeader::from_bytes(buf);
                Ok(header.to_rdma_message(buf.len())?)
            }
            Ok(RdmaOpcode::RdmaWriteMiddle) => {
                let header = RdmaWriteMiddleHeader::from_bytes(buf);
                Ok(header.to_rdma_message(buf.len())?)
            }
            Ok(RdmaOpcode::RdmaWriteLast) => {
                let header = RdmaWriteLastHeader::from_bytes(buf);
                Ok(header.to_rdma_message(buf.len())?)
            }
            Ok(RdmaOpcode::RdmaWriteLastWithImmediate) => {
                let header = RdmaWriteLastWithImmediateHeader::from_bytes(buf);
                Ok(header.to_rdma_message(buf.len())?)
            }
            Ok(RdmaOpcode::RdmaWriteOnly) => {
                let header = RdmaWriteOnlyHeader::from_bytes(buf);
                Ok(header.to_rdma_message(buf.len())?)
            }
            Ok(RdmaOpcode::RdmaWriteOnlyWithImmediate) => {
                let header = RdmaWriteOnlyWithImmediateHeader::from_bytes(buf);
                Ok(header.to_rdma_message(buf.len())?)
            }
            Ok(RdmaOpcode::RdmaReadRequest) => {
                let header = RdmaReadRequestHeader::from_bytes(buf);
                Ok(header.to_rdma_message(buf.len())?)
            }
            Ok(RdmaOpcode::RdmaReadResponseFirst) => {
                let header = RdmaReadResponseFirstHeader::from_bytes(buf);
                Ok(header.to_rdma_message(buf.len())?)
            }
            Ok(RdmaOpcode::RdmaReadResponseMiddle) => {
                let header = RdmaReadResponseMiddleHeader::from_bytes(buf);
                Ok(header.to_rdma_message(buf.len())?)
            }
            Ok(RdmaOpcode::RdmaReadResponseLast) => {
                let header = RdmaReadResponseLastHeader::from_bytes(buf);
                Ok(header.to_rdma_message(buf.len())?)
            }
            Ok(RdmaOpcode::RdmaReadResponseOnly) => {
                let header = RdmaReadResponseOnlyHeader::from_bytes(buf);
                Ok(header.to_rdma_message(buf.len())?)
            }
            Ok(RdmaOpcode::Acknowledge) => {
                let header = RdmaAcknowledgeHeader::from_bytes(buf);
                Ok(header.to_rdma_message(buf.len())?)
            }
            Err(_) => Err(PacketError::InvalidOpcode),
            _ => Err(PacketError::InvalidOpcode),
        }
    }

    pub fn set_from_rdma_message(
        &self,
        buf: &mut [u8],
        message: &RdmaMessage,
    ) -> Result<usize, PacketError> {
        match message.meta_data.get_opcode() {
            RdmaOpcode::RdmaWriteFirst => {
                let header = RdmaWriteFirstHeader::from_bytes(buf);
                header.set_from_rdma_message(message)?;
                Ok(size_of_val(header))
            }
            RdmaOpcode::RdmaWriteMiddle => {
                let header = RdmaWriteMiddleHeader::from_bytes(buf);
                header.set_from_rdma_message(message)?;
                Ok(size_of_val(header))
            }
            RdmaOpcode::RdmaWriteLast => {
                let header = RdmaWriteLastHeader::from_bytes(buf);
                header.set_from_rdma_message(message)?;
                Ok(size_of_val(header))
            }
            RdmaOpcode::RdmaWriteLastWithImmediate => {
                let header = RdmaWriteLastWithImmediateHeader::from_bytes(buf);
                header.set_from_rdma_message(message)?;
                Ok(size_of_val(header))
            }
            RdmaOpcode::RdmaWriteOnly => {
                let header = RdmaWriteOnlyHeader::from_bytes(buf);
                header.set_from_rdma_message(message)?;
                Ok(size_of_val(header))
            }
            RdmaOpcode::RdmaWriteOnlyWithImmediate => {
                let header = RdmaWriteOnlyWithImmediateHeader::from_bytes(buf);
                header.set_from_rdma_message(message)?;
                Ok(size_of_val(header))
            }
            RdmaOpcode::RdmaReadRequest => {
                let header = RdmaReadRequestHeader::from_bytes(buf);
                header.set_from_rdma_message(message)?;
                Ok(size_of_val(header))
            }
            RdmaOpcode::RdmaReadResponseFirst => {
                let header = RdmaReadResponseFirstHeader::from_bytes(buf);
                header.set_from_rdma_message(message)?;
                Ok(size_of_val(header))
            }
            RdmaOpcode::RdmaReadResponseMiddle => {
                let header = RdmaReadResponseMiddleHeader::from_bytes(buf);
                header.set_from_rdma_message(message)?;
                Ok(size_of_val(header))
            }
            RdmaOpcode::RdmaReadResponseLast => {
                let header = RdmaReadResponseLastHeader::from_bytes(buf);
                header.set_from_rdma_message(message)?;
                Ok(size_of_val(header))
            }
            RdmaOpcode::RdmaReadResponseOnly => {
                let header = RdmaReadResponseOnlyHeader::from_bytes(buf);
                header.set_from_rdma_message(message)?;
                Ok(size_of_val(header))
            }
            RdmaOpcode::Acknowledge => {
                let header = RdmaAcknowledgeHeader::from_bytes(buf);
                header.set_from_rdma_message(message)?;
                Ok(size_of_val(header))
            }
            _ => Err(PacketError::InvalidOpcode),
        }
    }
}

#[derive(Error, Debug)]
pub(crate) enum PacketProcessorError {
    #[error("missing packet_type")]
    MissingPacketType,
    #[error("missing src_addr")]
    MissingSrcAddr,
    #[error("missing src_port")]
    MissingSrcPort,
    #[error("missing dest_addr")]
    MissingDestAddr,
    #[error("missing dest_port")]
    MissingDestPort,
    #[error("missing payload")]
    MissingPayload,
    #[error("missing message")]
    MissingMessage,
    #[error("missing ip identification")]
    MissingIpId,
    #[error("Needs a buffer of at least {0} bytes, but got {1} bytes")]
    BufferNotLargeEnough(u32, u32),
    #[error("packet error")]
    PacketError(#[from] PacketError),
}

/// The type of packet to write. Used by `PacketWriter`
pub(crate) enum PacketWriterType {
    /// Raw packet
    Raw, 
    /// RDMA packet
    Rdma,
}

/// A builder for writing a packet
pub(crate) struct PacketWriter<'buf, 'payloadinfo, 'message> {
    buf: &'buf mut [u8],
    packet_type: Option<PacketWriterType>,
    src_addr: Option<Ipv4Addr>,
    src_port: Option<u16>,
    dest_addr: Option<Ipv4Addr>,
    dest_port: Option<u16>,
    payload: Option<&'payloadinfo PayloadInfo>,
    message: Option<&'message RdmaMessage>,
    ip_id: Option<u16>,
}

impl<'buf, 'payloadinfo, 'message> PacketWriter<'buf, 'payloadinfo, 'message> {
    pub fn new(buf: &'buf mut [u8]) -> Self {
        Self {
            buf,
            packet_type: None,
            src_addr: None,
            src_port: None,
            dest_addr: None,
            dest_port: None,
            payload: None,
            message: None,
            ip_id: None,
        }
    }

    pub fn packet_type(&mut self, type_: PacketWriterType) -> &mut Self {
        let new = self;
        new.packet_type = Some(type_);
        new
    }

    pub fn src_addr(&mut self, addr: Ipv4Addr) -> &mut Self {
        let new = self;
        new.src_addr = Some(addr);
        new
    }

    pub fn src_port(&mut self, port: u16) -> &mut Self {
        let new = self;
        new.src_port = Some(port);
        new
    }

    pub fn dest_addr(&mut self, addr: Ipv4Addr) -> &mut Self {
        let new = self;
        new.dest_addr = Some(addr);
        new
    }

    pub fn dest_port(&mut self, port: u16) -> &mut Self {
        let new = self;
        new.dest_port = Some(port);
        new
    }

    pub fn ip_id(&mut self, id: u16) -> &mut Self {
        let new = self;
        new.ip_id = Some(id);
        new
    }

    pub fn payload(&mut self, payload: &'payloadinfo PayloadInfo) -> &mut Self {
        let new = self;
        new.payload = Some(payload);
        new
    }

    pub fn message(&mut self, message: &'message RdmaMessage) -> &mut Self {
        let new = self;
        new.message = Some(message);
        new
    }

    pub fn write(&mut self) -> Result<usize, PacketProcessorError> {
        match self.packet_type {
            Some(PacketWriterType::Raw) => {
                let payload = self.payload.ok_or(PacketProcessorError::MissingPayload)?;

                // get the total length(include the ip,udp header and the icrc)
                let total_length = size_of::<IpUdpHeaders>() + payload.get_length();

                // write the payload
                let header_offset = size_of::<IpUdpHeaders>();
                payload.copy_to(self.buf[header_offset..].as_mut_ptr());

                // write the ip,udp header
                let ip_id = self.ip_id.ok_or(PacketProcessorError::MissingIpId)?;
                let src_addr = self.src_addr.ok_or(PacketProcessorError::MissingSrcAddr)?;
                let src_port = self.src_port.ok_or(PacketProcessorError::MissingSrcPort)?;
                let dest_addr = self
                    .dest_addr
                    .ok_or(PacketProcessorError::MissingDestAddr)?;
                let dest_port = self
                    .dest_port
                    .ok_or(PacketProcessorError::MissingDestPort)?;
                write_ip_udp_header(
                    self.buf,
                    src_addr,
                    src_port,
                    dest_addr,
                    dest_port,
                    total_length,
                    ip_id,
                );
                Ok(total_length)
            }
            Some(PacketWriterType::Rdma) => {
                let processor = PacketProcessor;
                // advance `size_of::<IpUdpHeaders>()` to write the rdma header
                let net_packet_offset = size_of::<IpUdpHeaders>();
                let message = self.message.ok_or(PacketProcessorError::MissingMessage)?;
                // write the rdma header
                let rdma_header_length =
                    processor.set_from_rdma_message(&mut self.buf[net_packet_offset..], message)?;

                // get the total length(include the ip,udp header and the icrc)
                let total_length = size_of::<IpUdpHeaders>()
                    + rdma_header_length
                    + message.payload.get_length()
                    + message.payload.with_pad_length()
                    + ICRC_SIZE;

                // write the payload
                let header_offset = size_of::<IpUdpHeaders>() + rdma_header_length;
                message
                    .payload
                    .copy_to(self.buf[header_offset..].as_mut_ptr());

                // write the ip,udp header
                let ip_id = self.ip_id.ok_or(PacketProcessorError::MissingIpId)?;
                let src_addr = self.src_addr.ok_or(PacketProcessorError::MissingSrcAddr)?;
                let src_port = self.src_port.ok_or(PacketProcessorError::MissingSrcPort)?;
                let dest_addr = self
                    .dest_addr
                    .ok_or(PacketProcessorError::MissingDestAddr)?;
                let dest_port = self
                    .dest_port
                    .ok_or(PacketProcessorError::MissingDestPort)?;
                write_ip_udp_header(
                    self.buf,
                    src_addr,
                    src_port,
                    dest_addr,
                    dest_port,
                    total_length,
                    ip_id,
                );

                // compute icrc
                let icrc = compute_icrc(&self.buf[..total_length])?.to_be_bytes();
                self.buf[total_length - ICRC_SIZE..total_length].copy_from_slice(&icrc);
                Ok(total_length)
            }
            None => Err(PacketProcessorError::MissingPacketType),
        }
    }
}

/// Assume the buffer is a packet, compute the icrc
/// Return a u32 of the icrc
pub(crate) fn compute_icrc(data: &[u8]) -> Result<u32, PacketProcessorError> {
    if data.len() < size_of::<CommonPacketHeader>() {
        return Err(PacketProcessorError::BufferNotLargeEnough(
            size_of::<CommonPacketHeader>() as u32,
            data.len() as u32,
        ));
    }

    let mut hasher = crc32fast::Hasher::new();
    let prefix = [0xffu8; 8];
    hasher.update(&prefix);

    let mut common_hdr = *CommonPacketHeader::from_bytes(data);
    let length = common_hdr.net_header.ip_header.get_pad_cnt();
    if data.len() != length as usize {
        return Err(PacketProcessorError::BufferNotLargeEnough(
            length as u32,
            data.len() as u32,
        ));
    }
    common_hdr.net_header.ip_header.dscp_ecn = 0xff;
    common_hdr.net_header.ip_header.ttl = 0xff;
    common_hdr.net_header.ip_header.set_checksum(0xffff);
    common_hdr.net_header.udp_header.set_checksum(0xffff);
    common_hdr.bth_header.fill_ecn_and_resv6();

    // convert common_hdr to bytes
    // SAFETY: the length is ensured
    let common_hdr_bytes = unsafe {
        std::slice::from_raw_parts(
            &common_hdr as *const CommonPacketHeader as *const u8,
            size_of::<CommonPacketHeader>(),
        )
    };
    hasher.update(common_hdr_bytes);
    // the rest of header and payload
    hasher.update(&data[size_of::<CommonPacketHeader>()..data.len() - 4]);

    Ok(hasher.finalize())
}

/// Write the ip and udp header to the buffer
/// 
/// # Panic
/// the buffer should be large enough to hold the ip and udp header
pub(crate) fn write_ip_udp_header(
    buf: &mut [u8],
    src_addr: Ipv4Addr,
    src_port: u16,
    dest_addr: Ipv4Addr,
    dest_port: u16,
    total_length: usize,
    ip_identification: u16,
) {
    let common_hdr = IpUdpHeaders::from_bytes(buf);
    common_hdr.ip_header.set_default_header();
    common_hdr.ip_header.set_source(src_addr);
    common_hdr.ip_header.set_destination(dest_addr);
    common_hdr.ip_header.set_total_length(total_length as u16);
    common_hdr.ip_header.set_flags_fragment_offset(0);
    common_hdr.ip_header.set_identification(ip_identification);
    common_hdr.ip_header.set_checksum(0);

    common_hdr.udp_header.set_source_port(src_port);
    common_hdr.udp_header.set_dest_port(dest_port);
    common_hdr
        .udp_header
        .set_length((total_length - size_of::<Ipv4Header>()) as u16);
    common_hdr.udp_header.set_checksum(0);
}

/// Assume the buffer is a packet, check if the icrc is valid
/// Return a bool if the icrc is valid
/// 
pub(crate) fn is_icrc_valid(received_data : &[u8]) -> Result<bool,PacketProcessorError>{
    let length = received_data.len();
    // chcek the icrc
    let icrc_array: [u8; 4] = match received_data[length - ICRC_SIZE..length].try_into() {
        Ok(arr) => arr,
        Err(_) => return Err(PacketProcessorError::BufferNotLargeEnough(ICRC_SIZE as u32, length as u32)),
    };
    let origin_icrc = u32::from_be_bytes(icrc_array);
    let our_icrc = compute_icrc(received_data);
    Ok(!(our_icrc.is_err() || our_icrc.unwrap() != origin_icrc))
}

#[test]
fn test_computing_icrc() {
    // The buffer is a packet in hex format:
    // IP(id=54321, frag=0,protocol= \
    //     ttl=128, dst="127.0.0.1", src="127.0.0.1", len=108)/ \
    //     UDP(sport=49152, dport=4791, len=88)/ \
    //     BTH(opcode='RC_RDMA_WRITE_MIDDLE',pkey=0x1, dqpn=3, psn=0)/ \
    //     Raw(bytes([0]*64))
    let buf: [u8; 108] = [
        0x45, 0x0, 0x0, 0x6c, 0xd4, 0x31, 0x0, 0x0, 0x80, 0x11, 0x68, 0x4d, 0x7f, 0x0, 0x0, 0x1,
        0x7f, 0x0, 0x0, 0x1, 0x30, 0x39, 0x12, 0xb7, 0x0, 0x58, 0x9, 0xdc, 0x7, 0x0, 0x0, 0x1, 0x0,
        0x0, 0x0, 0x3, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
        0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
        0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
        0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x00,
        0x00, 0x00, 0x00,
    ];
    let icrc = compute_icrc(&buf).unwrap();
    assert!(icrc == 0xbff3abb9, "icrc: {:x}", icrc);
}
