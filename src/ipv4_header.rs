#[derive(Debug)]
pub struct IpV4Header {
    // indicate the IP protocole version, such as IPv4 or IPv6
    pub version: u8,
    // total packet length, data payload + the header
    pub ihl: u8,
    // time to live
    pub ttl: u8,
    // high-level protocole, TCP | UDP... used in the data payload
    pub protocole: u8,
    // the IP header checksum
    // pub header_checksum: u32,
    // source IP Address
    pub source: [u8; 4],
    // Destination IP Adress
    pub destination: [u8; 4],
}
