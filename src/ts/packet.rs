/// 188-byte MPEG-TS packet parser.

pub const TS_PACKET_SIZE: usize = 188;
pub const SYNC_BYTE: u8 = 0x47;

#[derive(Debug, Clone)]
pub struct TsHeader {
    pub sync: u8,
    pub transport_error: bool,
    pub pusi: bool,
    pub transport_priority: bool,
    pub pid: u16,
    pub scrambling_control: u8,
    pub adaptation_field_control: u8,
    pub continuity_counter: u8,
}

#[derive(Debug, Clone)]
pub struct TsPacket<'a> {
    pub header: TsHeader,
    /// Raw 188 bytes of the packet.
    pub raw: &'a [u8],
    /// Byte offset of the payload within `raw`.
    pub payload_offset: usize,
    /// Length of the payload.
    pub payload_len: usize,
}

impl<'a> TsPacket<'a> {
    pub fn payload(&self) -> &'a [u8] {
        &self.raw[self.payload_offset..self.payload_offset + self.payload_len]
    }
}

/// Parse a single TS packet from a 188-byte slice.
pub fn parse_packet(data: &[u8]) -> Option<TsPacket<'_>> {
    if data.len() < TS_PACKET_SIZE || data[0] != SYNC_BYTE {
        return None;
    }

    let b1 = data[1];
    let b2 = data[2];
    let b3 = data[3];

    let header = TsHeader {
        sync: SYNC_BYTE,
        transport_error: (b1 & 0x80) != 0,
        pusi: (b1 & 0x40) != 0,
        transport_priority: (b1 & 0x20) != 0,
        pid: u16::from(b1 & 0x1F) << 8 | u16::from(b2),
        scrambling_control: (b3 >> 6) & 0x03,
        adaptation_field_control: (b3 >> 4) & 0x03,
        continuity_counter: b3 & 0x0F,
    };

    let mut payload_offset = 4usize;

    // adaptation_field_control: 0b10 = adaptation only, 0b11 = adaptation + payload
    if header.adaptation_field_control >= 2 {
        if payload_offset >= TS_PACKET_SIZE {
            return None;
        }
        let af_len = data[payload_offset] as usize;
        payload_offset += 1 + af_len;
    }

    let payload_len = if header.adaptation_field_control & 0x01 != 0 {
        // Has payload.
        TS_PACKET_SIZE.saturating_sub(payload_offset)
    } else {
        0
    };

    Some(TsPacket {
        header,
        raw: &data[..TS_PACKET_SIZE],
        payload_offset,
        payload_len,
    })
}

/// Iterate over all 188-byte TS packets in a buffer.
pub fn iter_packets(data: &[u8]) -> impl Iterator<Item = (usize, TsPacket<'_>)> {
    data.chunks(TS_PACKET_SIZE)
        .enumerate()
        .filter_map(|(i, chunk)| {
            let offset = i * TS_PACKET_SIZE;
            parse_packet(chunk).map(|pkt| (offset, pkt))
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_packet(pid: u16, pusi: bool, payload: &[u8]) -> [u8; TS_PACKET_SIZE] {
        let mut buf = [0xFFu8; TS_PACKET_SIZE];
        buf[0] = SYNC_BYTE;
        let pid_hi = ((pid >> 8) & 0x1F) as u8;
        let pid_lo = (pid & 0xFF) as u8;
        buf[1] = pid_hi | if pusi { 0x40 } else { 0 };
        buf[2] = pid_lo;
        buf[3] = 0x10; // adaptation_field_control = 0b01 (payload only), cc=0
        let len = payload.len().min(TS_PACKET_SIZE - 4);
        buf[4..4 + len].copy_from_slice(&payload[..len]);
        buf
    }

    #[test]
    fn parse_basic_packet() {
        let pkt_data = make_packet(0x100, true, &[0xAA; 10]);
        let pkt = parse_packet(&pkt_data).unwrap();
        assert_eq!(pkt.header.pid, 0x100);
        assert!(pkt.header.pusi);
        assert_eq!(pkt.payload_offset, 4);
        assert_eq!(pkt.payload_len, 184);
        assert_eq!(pkt.payload()[0], 0xAA);
    }

    #[test]
    fn parse_with_adaptation_field() {
        let mut buf = [0xFFu8; TS_PACKET_SIZE];
        buf[0] = SYNC_BYTE;
        buf[1] = 0x41; // PUSI + PID high = 0x01
        buf[2] = 0x00; // PID low = 0x00 → PID = 0x100
        buf[3] = 0x30; // adaptation + payload, cc=0
        buf[4] = 7; // adaptation field length = 7
        // adaptation field bytes [5..12] are don't-care
        // payload starts at offset 12
        buf[12] = 0xBB;
        let pkt = parse_packet(&buf).unwrap();
        assert_eq!(pkt.payload_offset, 12);
        assert_eq!(pkt.payload_len, 176);
        assert_eq!(pkt.payload()[0], 0xBB);
    }

    #[test]
    fn reject_bad_sync() {
        let mut buf = [0u8; TS_PACKET_SIZE];
        buf[0] = 0x00;
        assert!(parse_packet(&buf).is_none());
    }

    #[test]
    fn iter_multiple_packets() {
        let p1 = make_packet(0x00, false, &[]);
        let p2 = make_packet(0x100, true, &[1, 2, 3]);
        let mut data = Vec::new();
        data.extend_from_slice(&p1);
        data.extend_from_slice(&p2);
        let packets: Vec<_> = iter_packets(&data).collect();
        assert_eq!(packets.len(), 2);
        assert_eq!(packets[0].1.header.pid, 0x00);
        assert_eq!(packets[1].1.header.pid, 0x100);
    }
}
