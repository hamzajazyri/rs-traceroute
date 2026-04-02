use std::fmt;
// default used in linux for debugger and idk....
static PACKET_PAYLOAD_LENGTH: usize = 56;

pub struct ICMPPacket {
    typ: u8,
    code: u8,
    identifier: u16,
    sequence: u16,
    payload: [u8; PACKET_PAYLOAD_LENGTH],
}

impl ICMPPacket {
    pub fn new() -> Self {
        Self {
            typ: 8,
            code: 0,
            identifier: Self::get_default_identifier(),
            sequence: 0,
            payload: [0u8; PACKET_PAYLOAD_LENGTH],
        }
    }

    pub fn from_recv_packet(packet: &[u8]) -> Self {
        // packet received format
        // [ IP HEADER (20 bytes) + ICMP HEADER + payload ]
        // remove header
        let packet = &packet[20..];

        let mut payload = [0u8; PACKET_PAYLOAD_LENGTH];
        let packet_payload = &packet[8..];
        let packet_payload_len = packet_payload.len().min(PACKET_PAYLOAD_LENGTH);

        println!("packet payload len {}", packet_payload_len);
        payload[..packet_payload_len].copy_from_slice(&packet_payload[..packet_payload_len]);

        Self {
            typ: packet[0],
            code: packet[1],
            identifier: ((packet[4] as u16) << 8) | packet[5] as u16,
            sequence: ((packet[6] as u16) << 8) | packet[7] as u16,
            payload,
        }
    }

    pub fn set_payload(&mut self, payload: String) {
        let payload = payload.into_bytes();
        if payload.len() > PACKET_PAYLOAD_LENGTH {
            panic!(
                "Payload is beginner than payload length, current: {}, max length {}",
                payload.len(),
                PACKET_PAYLOAD_LENGTH
            );
        }
        self.payload[0..payload.len()].copy_from_slice(&payload);
    }

    fn get_default_identifier() -> u16 {
        std::process::id() as u16
    }

    fn calculate_checksum(packet: &[u8]) -> u16 {
        let mut sum = 0u32;

        let mut counter = 0;

        while counter + 1 < packet.len() {
            let p_sum = ((packet[counter] as u16) << 8) + packet[counter + 1] as u16;

            sum += p_sum as u32;
            counter += 2;
        }

        if counter < packet.len() {
            sum += (packet[counter] as u32) << 8;
        }

        while (sum >> 16) != 0 {
            sum = (sum & 0x0000FFFF) + (sum >> 16);
        }

        !(sum as u16)
    }

    fn build_header(&self) -> [u8; 8] {
        let mut packet = [0u8; 8];
        packet[0] = self.typ;
        packet[1] = self.code;
        // checksum
        // packet[2] = 0u8;
        // packet[3] = 0u8;
        packet[4..6].copy_from_slice(&self.identifier.to_be_bytes());
        packet[6..8].copy_from_slice(&self.sequence.to_be_bytes());
        packet
    }

    pub fn build_packet(&self) -> Vec<u8> {
        let header = self.build_header();

        let mut packet: Vec<u8> = Vec::with_capacity(header.len() + PACKET_PAYLOAD_LENGTH);
        packet.extend_from_slice(&header);
        packet.extend_from_slice(&self.payload);

        let checksum = Self::calculate_checksum(&packet);

        packet[2..4].copy_from_slice(&checksum.to_be_bytes());
        packet
    }
}

impl Default for ICMPPacket {
    fn default() -> Self {
        Self::new()
    }
}
impl fmt::Debug for ICMPPacket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ICMPPacket {{ ")?;
        write!(f, "\n\rtype: {},\n\rcode: {}, ", self.typ, self.code)?;
        write!(
            f,
            "\n\ridentifier: {}, \n\rsequence: {}, ",
            self.identifier, self.sequence
        )?;

        // 👇 custom payload formatting
        write!(f, "\n\rpayload: ")?;

        for &b in &self.payload {
            if b.is_ascii_graphic() || b == b' ' {
                write!(f, "{}", b as char);
            } else {
                write!(f, "<*>");
            }
        }

        write!(f, "}}")
    }
}
