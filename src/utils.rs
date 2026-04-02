use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs};

use libc::sockaddr_in;

pub fn resolve_domain(host: &str) -> Option<Ipv4Addr> {
    // addr: [IPV4, IPV6]
    let addr: Vec<SocketAddr> = (host, 0).to_socket_addrs().unwrap().collect();

    let mut addr_ipv4: Vec<Ipv4Addr> = Vec::new();
    let mut addr_ipv6: Vec<Ipv6Addr> = Vec::new();

    for add in addr {
        match add.ip() {
            IpAddr::V4(ipv4) => addr_ipv4.push(ipv4),
            IpAddr::V6(ipv6) => addr_ipv6.push(ipv6),
        };
    }

    if addr_ipv4.is_empty() {
        None
    } else {
        Some(addr_ipv4[0])
    }
}

pub fn ipv4_to_sockaddr_in(destination: &Ipv4Addr) -> sockaddr_in {
    let mut dest: sockaddr_in = unsafe { std::mem::zeroed() };
    dest.sin_family = libc::AF_INET as u16;
    dest.sin_addr.s_addr = (*destination).into();
    dest
}
