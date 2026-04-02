use traceroute::cli::parse_cli_args;
use traceroute::icmp::ICMPPacket;
use traceroute::socket::Socket;
use traceroute::utils::resolve_domain;

fn main() {
    let args = parse_cli_args();

    dbg!(&args);

    // convert host to ipv4
    let ipv4 = resolve_domain(args.host());

    if let Some(ip) = ipv4 {
        let mut builder = ICMPPacket::new();
        builder.set_payload(String::from("this is my packet"));

        // get packet as [u8] following icmp packet format
        let packet = builder.build_packet();

        let mut socket = Socket::new(ip, &packet);
        socket.init_socket();

        socket.set_ttl(100);
        socket.send_socket();
        let data: &[u8] = &socket.receive_socket();
        let packet: ICMPPacket = ICMPPacket::from_recv_packet(data);
        dbg!(&packet);

        socket.set_ttl(2);
        socket.send_socket();
        let data: &[u8] = &socket.receive_socket();
        let packet: ICMPPacket = ICMPPacket::from_recv_packet(data);
        dbg!(&packet);
    } else {
        panic!("cannot resolve IP");
    }
}

use libc::{recvfrom, sockaddr_in, socklen_t};

pub fn receive_packet(socket: i32) {
    let mut buffer = [0u8; 1024];

    let mut addr: sockaddr_in = unsafe { std::mem::zeroed() };
    let mut addr_len = std::mem::size_of::<sockaddr_in>() as socklen_t;

    let received = unsafe {
        recvfrom(
            socket,
            buffer.as_mut_ptr() as *mut _,
            buffer.len(),
            0,
            &mut addr as *mut _ as *mut _,
            &mut addr_len as *mut _,
        )
    };

    if received < 0 {
        println!("recvfrom failed");
        return;
    }

    println!("Received {} bytes", received);

    let data = &buffer[..received as usize];
    println!("Raw packet: {:?}", data);
}
