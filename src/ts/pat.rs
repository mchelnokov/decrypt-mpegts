/// Program Association Table parser.
///
/// PAT is always on PID 0x0000. It maps program_number → PMT PID.

use crate::error::{Error, Result};
use crate::ts::packet::iter_packets;

/// Entry from the PAT: one program.
#[derive(Debug, Clone)]
pub struct PatEntry {
    pub program_number: u16,
    pub pmt_pid: u16,
}

/// Parse PAT from accumulated section payload bytes.
/// The payload should begin right after the pointer field adjustment.
fn parse_pat_section(section: &[u8]) -> Vec<PatEntry> {
    // Minimum section: table_id(1) + flags(2) + id(2) + version(1) + section(1) + last_section(1) + CRC(4) = 12
    if section.len() < 12 {
        return Vec::new();
    }

    let section_length = (u16::from(section[1] & 0x0F) << 8 | u16::from(section[2])) as usize;
    let end = (3 + section_length).min(section.len());

    // Program loop starts at byte 8, ends 4 bytes before section end (CRC32).
    let loop_start = 8;
    let loop_end = end.saturating_sub(4);

    let mut entries = Vec::new();
    let mut i = loop_start;
    while i + 4 <= loop_end {
        let program_number = u16::from(section[i]) << 8 | u16::from(section[i + 1]);
        let pid = u16::from(section[i + 2] & 0x1F) << 8 | u16::from(section[i + 3]);
        if program_number != 0 {
            // program_number 0 is NIT, skip it
            entries.push(PatEntry {
                program_number,
                pmt_pid: pid,
            });
        }
        i += 4;
    }
    entries
}

/// Scan packets for the PAT and return program entries.
pub fn find_pat(data: &[u8]) -> Result<Vec<PatEntry>> {
    for (_offset, pkt) in iter_packets(data) {
        if pkt.header.pid != 0x0000 {
            continue;
        }
        let payload = pkt.payload();
        if payload.is_empty() {
            continue;
        }
        // pointer_field
        let pointer = payload[0] as usize;
        let section_start = 1 + pointer;
        if section_start >= payload.len() {
            continue;
        }
        let entries = parse_pat_section(&payload[section_start..]);
        if !entries.is_empty() {
            return Ok(entries);
        }
    }
    Err(Error::PatNotFound)
}

/// Convenience: find the first PMT PID.
pub fn find_pmt_pid(data: &[u8]) -> Result<u16> {
    let entries = find_pat(data)?;
    entries
        .first()
        .map(|e| e.pmt_pid)
        .ok_or(Error::PatNotFound)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ts::packet::{SYNC_BYTE, TS_PACKET_SIZE};

    /// Build a minimal PAT packet.
    fn build_pat_packet(program_number: u16, pmt_pid: u16) -> [u8; TS_PACKET_SIZE] {
        let mut buf = [0xFFu8; TS_PACKET_SIZE];
        buf[0] = SYNC_BYTE;
        buf[1] = 0x40; // PUSI=1, PID=0x0000
        buf[2] = 0x00;
        buf[3] = 0x10; // payload only

        // Pointer field
        buf[4] = 0x00;

        // PAT section
        buf[5] = 0x00; // table_id = 0
        // section_length = 13 (5 header after length + 4 program + 4 CRC)
        buf[6] = 0xB0;
        buf[7] = 13;
        // transport_stream_id
        buf[8] = 0x00;
        buf[9] = 0x01;
        // version/current
        buf[10] = 0xC1;
        // section_number
        buf[11] = 0x00;
        // last_section_number
        buf[12] = 0x00;
        // program entry
        buf[13] = (program_number >> 8) as u8;
        buf[14] = (program_number & 0xFF) as u8;
        buf[15] = 0xE0 | ((pmt_pid >> 8) & 0x1F) as u8;
        buf[16] = (pmt_pid & 0xFF) as u8;
        // CRC (dummy)
        buf[17] = 0x00;
        buf[18] = 0x00;
        buf[19] = 0x00;
        buf[20] = 0x00;

        buf
    }

    #[test]
    fn parse_pat_finds_pmt_pid() {
        let pkt = build_pat_packet(1, 0x1000);
        let entries = find_pat(&pkt).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].program_number, 1);
        assert_eq!(entries[0].pmt_pid, 0x1000);
    }

    #[test]
    fn find_pmt_pid_convenience() {
        let pkt = build_pat_packet(1, 0x100);
        assert_eq!(find_pmt_pid(&pkt).unwrap(), 0x100);
    }
}
