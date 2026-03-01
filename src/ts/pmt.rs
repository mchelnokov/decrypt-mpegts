/// Program Map Table parser.
///
/// Maps elementary stream PIDs to their stream types.

use crate::error::{Error, Result};
use crate::ts::packet::iter_packets;
use std::collections::HashMap;

/// Known stream types for sample encryption.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamType {
    H264,
    Aac,
    Ac3,
    Other(u8),
}

impl StreamType {
    pub fn from_byte(b: u8) -> Self {
        match b {
            0x1B | 0xDB => StreamType::H264, // 0xDB = FairPlay-encrypted H.264
            0x0F | 0xCF => StreamType::Aac,  // 0xCF = FairPlay-encrypted AAC
            0x81 | 0xC1 => StreamType::Ac3,  // 0xC1 = FairPlay-encrypted AC-3
            other => StreamType::Other(other),
        }
    }
}

/// A single elementary stream entry from the PMT.
#[derive(Debug, Clone)]
pub struct PmtStream {
    pub stream_type: StreamType,
    pub raw_type_byte: u8,
    pub pid: u16,
}

/// Parse a PMT section payload (after pointer field adjustment).
fn parse_pmt_section(section: &[u8]) -> Vec<PmtStream> {
    // table_id(1) + section_length(2) + program_number(2) + version(1) + section_num(1) + last_section(1) + PCR_PID(2) + program_info_length(2) = 12 + CRC(4)
    if section.len() < 16 {
        return Vec::new();
    }

    let section_length = (u16::from(section[1] & 0x0F) << 8 | u16::from(section[2])) as usize;
    let end = (3 + section_length).min(section.len());

    // program_info_length at bytes 10-11
    let prog_info_len =
        (u16::from(section[10] & 0x0F) << 8 | u16::from(section[11])) as usize;

    let mut i = 12 + prog_info_len;
    let loop_end = end.saturating_sub(4); // exclude CRC

    let mut streams = Vec::new();
    while i + 5 <= loop_end {
        let stream_type_byte = section[i];
        let es_pid = u16::from(section[i + 1] & 0x1F) << 8 | u16::from(section[i + 2]);
        let es_info_len =
            (u16::from(section[i + 3] & 0x0F) << 8 | u16::from(section[i + 4])) as usize;

        streams.push(PmtStream {
            stream_type: StreamType::from_byte(stream_type_byte),
            raw_type_byte: stream_type_byte,
            pid: es_pid,
        });

        i += 5 + es_info_len;
    }

    streams
}

/// Scan the TS data for a PMT with the given PID and return PID → (StreamType, raw_byte) map.
pub fn find_pmt(data: &[u8], pmt_pid: u16) -> Result<HashMap<u16, (StreamType, u8)>> {
    for (_offset, pkt) in iter_packets(data) {
        if pkt.header.pid != pmt_pid {
            continue;
        }
        let payload = pkt.payload();
        if payload.is_empty() {
            continue;
        }
        let pointer = payload[0] as usize;
        let section_start = 1 + pointer;
        if section_start >= payload.len() {
            continue;
        }

        let streams = parse_pmt_section(&payload[section_start..]);
        if !streams.is_empty() {
            let map: HashMap<u16, (StreamType, u8)> = streams
                .into_iter()
                .map(|s| (s.pid, (s.stream_type, s.raw_type_byte)))
                .collect();
            return Ok(map);
        }
    }
    Err(Error::PmtNotFound(pmt_pid))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ts::packet::{SYNC_BYTE, TS_PACKET_SIZE};

    fn build_pmt_packet(
        pmt_pid: u16,
        entries: &[(u8, u16)], // (stream_type, es_pid)
    ) -> [u8; TS_PACKET_SIZE] {
        let mut buf = [0xFFu8; TS_PACKET_SIZE];
        buf[0] = SYNC_BYTE;
        buf[1] = 0x40 | ((pmt_pid >> 8) & 0x1F) as u8;
        buf[2] = (pmt_pid & 0xFF) as u8;
        buf[3] = 0x10; // payload only

        let mut off = 4;
        // pointer field
        buf[off] = 0x00;
        off += 1;

        let section_start = off;
        // table_id = 0x02 (PMT)
        buf[off] = 0x02;
        off += 1;

        // section_length placeholder (fill later)
        let section_length_pos = off;
        buf[off] = 0xB0;
        off += 1;
        buf[off] = 0x00; // placeholder
        off += 1;

        // program_number
        buf[off] = 0x00;
        buf[off + 1] = 0x01;
        off += 2;

        // version/current
        buf[off] = 0xC1;
        off += 1;

        // section_number
        buf[off] = 0x00;
        off += 1;

        // last_section_number
        buf[off] = 0x00;
        off += 1;

        // PCR PID (0x1FFF = none)
        buf[off] = 0xE1;
        buf[off + 1] = 0xFF;
        off += 2;

        // program_info_length = 0
        buf[off] = 0xF0;
        buf[off + 1] = 0x00;
        off += 2;

        // ES entries
        for &(stype, es_pid) in entries {
            buf[off] = stype;
            buf[off + 1] = 0xE0 | ((es_pid >> 8) & 0x1F) as u8;
            buf[off + 2] = (es_pid & 0xFF) as u8;
            buf[off + 3] = 0xF0;
            buf[off + 4] = 0x00; // es_info_length = 0
            off += 5;
        }

        // CRC (dummy)
        buf[off] = 0x00;
        buf[off + 1] = 0x00;
        buf[off + 2] = 0x00;
        buf[off + 3] = 0x00;
        off += 4;

        // Fill in section_length
        let section_length = off - section_start - 3;
        buf[section_length_pos] = 0xB0;
        buf[section_length_pos + 1] = section_length as u8;

        buf
    }

    #[test]
    fn parse_pmt_finds_streams() {
        let pkt = build_pmt_packet(0x100, &[(0x1B, 0x101), (0x0F, 0x102)]);
        let map = find_pmt(&pkt, 0x100).unwrap();
        assert_eq!(map.len(), 2);
        assert_eq!(map[&0x101].0, StreamType::H264);
        assert_eq!(map[&0x101].1, 0x1B);
        assert_eq!(map[&0x102].0, StreamType::Aac);
        assert_eq!(map[&0x102].1, 0x0F);
    }
}
