use std::net::Ipv4Addr;

use libc::{
    AF_INET, IP_TTL, IPPROTO_ICMP, IPPROTO_IP, SOCK_RAW, sendto, setsockopt, sockaddr_in, socket,
};

use crate::utils::ipv4_to_sockaddr_in;

pub struct Socket<'a> {
    destination: Ipv4Addr,
    ttl: Option<u32>,
    packet: &'a [u8],

    socket: i32,
}

impl<'a> Socket<'a> {
    pub fn new(destination: Ipv4Addr, packet: &'a [u8]) -> Self {
        Self {
            destination,
            ttl: None,
            packet,
            socket: 0,
        }
    }

    pub fn init_socket(&mut self) {
        self.socket = unsafe { socket(AF_INET, SOCK_RAW, IPPROTO_ICMP) };
        if self.socket < 0 {
            panic!("failed to create socket. Try running with sudo...");
        }
    }

    pub fn set_ttl(&mut self, ttl: u32) {
        self.ttl = Some(ttl);
        self.init_options();
    }

    fn init_options(&self) {
        if let Some(ttl) = self.ttl {
            unsafe {
                setsockopt(
                    self.socket,
                    IPPROTO_IP,
                    IP_TTL,
                    &ttl as *const _ as *const _,
                    std::mem::size_of::<u32>() as u32,
                )
            };
        }
    }

    pub fn send_socket(&self) {
        let sent = unsafe {
            sendto(
                self.socket,
                self.packet.as_ptr() as *const _,
                self.packet.len(),
                0,
                &ipv4_to_sockaddr_in(&self.destination) as *const _ as *const _,
                std::mem::size_of::<sockaddr_in>() as u32,
            )
        };

        if sent < 0 {
            println!("Error sending packet");
        } else {
            println!("Sent {} bytes to {}", sent, self.destination);
        }
    }

    // return full packet
    // includes IP HEADER + ICMP HEADER + PAYLOAD
    pub fn receive_socket(&self) -> Vec<u8> {
        let mut buffer = [0u8; 1024];
        let mut addr = ipv4_to_sockaddr_in(&Ipv4Addr::new(0, 0, 0, 0));
        let mut addr_len = std::mem::size_of::<sockaddr_in>() as libc::socklen_t;

        let received = unsafe {
            libc::recvfrom(
                self.socket,
                buffer.as_mut_ptr() as *mut _,
                buffer.len(),
                0,
                &mut addr as *mut _ as *mut _,
                &mut addr_len as *mut _,
            )
        };

        if received < 0 {
            println!("receive failed");
        }

        println!("Received {} bytes", received);
        let data: &[u8] = &buffer[0..received as usize];

        println!("raw packet {:?}", data);
        data.to_owned()
    }
}
