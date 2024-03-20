use std::{
    mem::{size_of, MaybeUninit},
    net::{Ipv4Addr, SocketAddrV4},
    os::fd::AsRawFd,
    sync::{atomic::AtomicU16, Arc},
    thread,
};

use socket2::{Domain, Protocol, Socket, Type};

use crate::device::software::{
    packet::{CommonPacketHeader, IpUdpHeaders, ICRC_SIZE},
    packet_processor::{is_icrc_valid, PacketProcessor, PacketWriter, PacketWriterType},
    types::{PayloadInfo, RdmaMessage},
};

use super::{NetAgentError, NetReceiveLogic, NetSendAgent};

pub const NET_SERVER_BUF_SIZE: usize = 4096;

/// A single thread udp server that listens to the corresponding port and calls the `recv` method of the receiver when a message is received.
pub struct UDPReceiveAgent {
    receiver: Arc<dyn for<'a> NetReceiveLogic<'a>>,
    listen_thread: Option<thread::JoinHandle<Result<(), NetAgentError>>>,
}

/// A udp client that sends messages to the corresponding address and port.
pub struct UDPSendAgent {
    sender: Socket,
    sending_id_counter: AtomicU16,
}

impl UDPSendAgent {
    pub fn new() -> Result<Self, NetAgentError> {
        let sender = Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::UDP))?;
        let fd = sender.as_raw_fd();
        unsafe {
            let on = 1i32;
            let ret = libc::setsockopt(
                fd,
                libc::IPPROTO_IP,
                libc::IP_HDRINCL,
                &on as *const _ as *const libc::c_void,
                std::mem::size_of_val(&on) as libc::socklen_t,
            );
            if ret != 0 {
                return Err(NetAgentError::SetSockOptFailed(ret));
            }
        }

        // We can use the `rand` crate as well.
        let rand_val = unsafe {
            // get a random number as the identification
            libc::srand(libc::time(std::ptr::null_mut()) as u32);
            libc::rand()
        };
        // it may truncation here.
        let sending_id = AtomicU16::new(rand_val as u16);
        Ok(Self {
            sender,
            sending_id_counter: sending_id,
        })
    }
}

impl UDPReceiveAgent {
    pub fn new(receiver: Arc<dyn for<'a> NetReceiveLogic<'a>>) -> Result<Self, NetAgentError> {
        Ok(Self {
            receiver,
            listen_thread: None,
        })
    }

    /// start a thread to listen to the corresponding port,
    /// and call the `recv` method of the receiver when a message is received.
    pub fn start(&mut self) -> Result<(), NetAgentError> {
        let receiver = self.receiver.clone();
        let socket = Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::UDP))?;
        let addr = SocketAddrV4::new(self.receiver.get_recv_addr(), self.receiver.get_recv_port());
        socket.bind(&addr.into())?;
        self.listen_thread = Some(thread::spawn(move || -> Result<(), NetAgentError> {
            let mut buf = [MaybeUninit::<u8>::uninit(); NET_SERVER_BUF_SIZE];
            let processor = PacketProcessor;
            loop {
                let (length, _src) = socket.recv_from(&mut buf)?;
                if length < size_of::<CommonPacketHeader>() + 4 {
                    continue;
                }
                // SAFETY: `recv_from` ensures that the buffer is filled with `length` bytes.
                let received_data =
                    unsafe { std::slice::from_raw_parts(buf.as_ptr() as *const u8, length) };

                if !is_icrc_valid(received_data)? {
                    continue;
                }
                // skip the ip header and udp header and the icrc
                let offset = size_of::<IpUdpHeaders>();
                let received_data = &received_data[offset..length - ICRC_SIZE];
                if let Ok(mut message) = processor.to_rdma_message(received_data) {
                    receiver.recv(&mut message);
                }
            }
        }));
        Ok(())
    }
}

impl NetSendAgent for UDPSendAgent {
    fn send(
        &self,
        dest_addr: Ipv4Addr,
        dest_port: u16,
        message: &RdmaMessage,
    ) -> Result<(), NetAgentError> {
        let mut buf = [0u8; NET_SERVER_BUF_SIZE];
        let src_addr = self.get_dest_addr();
        let src_port = self.get_dest_port();
        let ip_id = self
            .sending_id_counter
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        let total_length = PacketWriter::new(&mut buf)
            .packet_type(PacketWriterType::Rdma)
            .src_addr(src_addr)
            .src_port(src_port)
            .dest_addr(dest_addr)
            .dest_port(dest_port)
            .ip_id(ip_id)
            .message(message)
            .write()?;

        self.sender.send_to(
            &buf[0..total_length],
            &SocketAddrV4::new(dest_addr, dest_port).into(),
        )?;
        Ok(())
    }

    fn send_raw(
        &self,
        dest_addr: Ipv4Addr,
        dest_port: u16,
        payload: &PayloadInfo,
    ) -> Result<(), NetAgentError> {
        let mut buf = [0u8; NET_SERVER_BUF_SIZE];
        let src_addr = self.get_dest_addr();
        let src_port = self.get_dest_port();
        let ip_id = self
            .sending_id_counter
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        let total_length = PacketWriter::new(&mut buf)
            .packet_type(PacketWriterType::Raw)
            .src_addr(src_addr)
            .src_port(src_port)
            .dest_addr(dest_addr)
            .dest_port(dest_port)
            .ip_id(ip_id)
            .payload(payload)
            .write()?;

        self.sender.send_to(
            &buf[0..total_length],
            &SocketAddrV4::new(dest_addr, dest_port).into(),
        )?;
        Ok(())
    }

    fn get_dest_addr(&self) -> Ipv4Addr {
        Ipv4Addr::LOCALHOST
    }

    fn get_dest_port(&self) -> u16 {
        4791
    }
}

#[cfg(test)]
mod tests {
    use std::{
        net::Ipv4Addr,
        sync::{Arc, Mutex},
    };

    use crate::device::software::{net_agent::NetReceiveLogic, types::RdmaMessage};
    struct DummyNetReceiveLogic {
        packets: Arc<Mutex<Vec<RdmaMessage>>>,
    }
    unsafe impl Sync for DummyNetReceiveLogic {}
    unsafe impl Send for DummyNetReceiveLogic {}

    impl NetReceiveLogic<'_> for DummyNetReceiveLogic {
        fn recv(&self, msg: &mut RdmaMessage) {
            let new_msg = msg.clone();
            self.packets.lock().unwrap().push(new_msg);
        }

        fn get_recv_addr(&self) -> Ipv4Addr {
            Ipv4Addr::LOCALHOST
        }

        fn get_recv_port(&self) -> u16 {
            4791
        }
    }
}
