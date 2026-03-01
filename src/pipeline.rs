/// Top-level decryption pipeline.
///
/// Elementary stream data (both H.264 and AAC/AC-3) can span PES boundaries.
/// For H.264, the encryption process inserts EPBs which shifts PES/NAL
/// alignment. For AAC, ADTS frames simply span PES boundaries.
///
/// To handle this correctly, ALL ES data for each encrypted PID is
/// concatenated, decrypted as one continuous stream, and then re-split into
/// PES packets matching the original per-PES ES sizes.

use std::collections::HashMap;
use std::fs;
use std::path::Path;

use log::{debug, info};

use crate::crypto::{aac, ac3, h264};
use crate::error::Result;
use crate::ts::packet::{iter_packets, TS_PACKET_SIZE};
use crate::ts::pat::find_pmt_pid;
use crate::ts::pes::pes_payload_offset;
use crate::ts::pmt::{find_pmt, StreamType};
use crate::ts::writer::packetize;

/// A buffered original TS packet for an encrypted PID.
#[derive(Clone)]
struct BufferedPacket {
    raw: [u8; TS_PACKET_SIZE],
    payload_offset: usize,
    payload_len: usize,
}

/// Metadata for one PES within a PID's stream.
struct PesMeta {
    pes_header: Vec<u8>,
    orig_es_size: usize,
    orig_packets: Vec<BufferedPacket>,
    cc_start: u8,
}

/// Write a PES to output, reusing original packet structure when sizes match.
fn write_pes_to_output(
    output: &mut Vec<u8>,
    pid: u16,
    pes_data: &[u8],
    orig_packets: &[BufferedPacket],
    cc_start: u8,
) {
    let orig_payload_size: usize = orig_packets.iter().map(|p| p.payload_len).sum();

    if pes_data.len() == orig_payload_size {
        // Sizes match — overwrite payload in original packet shells.
        let mut pes_offset = 0;
        for pkt in orig_packets {
            let mut raw = pkt.raw;
            // Clear scrambling control bits.
            raw[3] &= 0x3F;
            if pkt.payload_len > 0 {
                raw[pkt.payload_offset..pkt.payload_offset + pkt.payload_len]
                    .copy_from_slice(&pes_data[pes_offset..pes_offset + pkt.payload_len]);
                pes_offset += pkt.payload_len;
            }
            output.extend_from_slice(&raw);
        }
    } else {
        // Size changed (EPB removal) — repacketize and pad with null packets.
        debug!(
            "PID {:#06x}: size changed ({} -> {}), repacketizing",
            pid, orig_payload_size, pes_data.len(),
        );
        let (new_packets, _) = packetize(pid, cc_start, pes_data);
        output.extend_from_slice(&new_packets);
        let new_count = new_packets.len() / TS_PACKET_SIZE;
        for _ in new_count..orig_packets.len() {
            let mut null_pkt = [0xFFu8; TS_PACKET_SIZE];
            null_pkt[0] = 0x47;
            null_pkt[1] = 0x1F;
            null_pkt[2] = 0xFF;
            null_pkt[3] = 0x10;
            output.extend_from_slice(&null_pkt);
        }
    }
}

/// Collect all PES for a PID, concatenate ES, decrypt, re-split.
fn preprocess_pid(
    data: &[u8],
    target_pid: u16,
    stream_type: StreamType,
    key: &[u8; 16],
    iv: &[u8; 16],
) -> Vec<(Vec<u8>, Vec<BufferedPacket>, u8)> {
    let mut pes_meta: Vec<PesMeta> = Vec::new();
    let mut full_es: Vec<u8> = Vec::new();
    let mut cur_buf: Vec<u8> = Vec::new();
    let mut cur_pkts: Vec<BufferedPacket> = Vec::new();
    let mut cur_cc: Option<u8> = None;

    let flush_cur = |buf: &mut Vec<u8>,
                     pkts: &mut Vec<BufferedPacket>,
                     cc: &mut Option<u8>,
                     pes_meta: &mut Vec<PesMeta>,
                     full_es: &mut Vec<u8>| {
        if buf.is_empty() {
            return;
        }
        let es_offset = pes_payload_offset(buf).unwrap_or(buf.len());
        let es_size = buf.len() - es_offset;
        full_es.extend_from_slice(&buf[es_offset..]);
        pes_meta.push(PesMeta {
            pes_header: buf[..es_offset].to_vec(),
            orig_es_size: es_size,
            orig_packets: std::mem::take(pkts),
            cc_start: cc.unwrap_or(0),
        });
        buf.clear();
        *cc = None;
    };

    for (_offset, pkt) in iter_packets(data) {
        if pkt.header.pid != target_pid {
            continue;
        }
        if pkt.header.pusi && !cur_buf.is_empty() {
            flush_cur(
                &mut cur_buf,
                &mut cur_pkts,
                &mut cur_cc,
                &mut pes_meta,
                &mut full_es,
            );
        }
        if cur_cc.is_none() {
            cur_cc = Some(pkt.header.continuity_counter);
        }
        if pkt.payload_len > 0 {
            cur_buf.extend_from_slice(
                &pkt.raw[pkt.payload_offset..pkt.payload_offset + pkt.payload_len],
            );
        }
        let mut raw = [0u8; TS_PACKET_SIZE];
        raw.copy_from_slice(pkt.raw);
        cur_pkts.push(BufferedPacket {
            raw,
            payload_offset: pkt.payload_offset,
            payload_len: pkt.payload_len,
        });
    }
    flush_cur(
        &mut cur_buf,
        &mut cur_pkts,
        &mut cur_cc,
        &mut pes_meta,
        &mut full_es,
    );

    info!(
        "PID {:#06x} ({:?}): {} PES, {} bytes ES",
        target_pid,
        stream_type,
        pes_meta.len(),
        full_es.len(),
    );

    // Decrypt the full concatenated ES.
    match stream_type {
        StreamType::H264 => h264::decrypt_h264(key, iv, &mut full_es),
        StreamType::Aac => aac::decrypt_aac(key, iv, &mut full_es),
        StreamType::Ac3 => ac3::decrypt_ac3(key, iv, &mut full_es),
        StreamType::Other(t) => {
            debug!("Unknown stream type {:#04x}, passing through", t);
        }
    }

    // Split decrypted ES back into per-PES chunks.
    let mut result = Vec::with_capacity(pes_meta.len());
    let mut cursor = 0usize;
    for meta in pes_meta {
        let available = full_es.len().saturating_sub(cursor);
        let take = meta.orig_es_size.min(available);
        let mut pes_data = meta.pes_header;
        pes_data.extend_from_slice(&full_es[cursor..cursor + take]);
        cursor += take;
        result.push((pes_data, meta.orig_packets, meta.cc_start));
    }

    result
}

/// Rebuild a PMT packet: fix FairPlay stream types and strip FairPlay descriptors.
fn patch_pmt_packet(raw: &mut [u8; TS_PACKET_SIZE], payload_offset: usize, payload_len: usize) {
    if payload_len == 0 || payload_offset >= TS_PACKET_SIZE {
        return;
    }

    let payload = &raw[payload_offset..payload_offset + payload_len];
    let pointer = payload[0] as usize;
    let section_start = 1 + pointer;
    if section_start >= payload.len() {
        return;
    }
    let section = &payload[section_start..];
    if section.len() < 16 {
        return;
    }

    let section_length =
        (u16::from(section[1] & 0x0F) << 8 | u16::from(section[2])) as usize;
    let end = (3 + section_length).min(section.len());
    let prog_info_len =
        (u16::from(section[10] & 0x0F) << 8 | u16::from(section[11])) as usize;

    // Parse ES entries, mapping FairPlay stream types back to standard ones.
    let mut entries: Vec<(u8, u16)> = Vec::new();
    let mut i = 12 + prog_info_len;
    let loop_end = end.saturating_sub(4);
    while i + 5 <= loop_end {
        let stream_type = match section[i] {
            0xDB => 0x1B, // H.264
            0xCF => 0x0F, // AAC
            0xC1 => 0x81, // AC-3
            other => other,
        };
        let es_pid = u16::from(section[i + 1] & 0x1F) << 8 | u16::from(section[i + 2]);
        entries.push((stream_type, es_pid));
        let es_info_len =
            (u16::from(section[i + 3] & 0x0F) << 8 | u16::from(section[i + 4])) as usize;
        i += 5 + es_info_len;
    }

    // Rewrite the PMT section with corrected stream types and no ES descriptors.
    let abs_section = payload_offset + section_start;
    let new_es_loop_len: usize = entries.len() * 5;
    let new_section_length = 9 + prog_info_len + new_es_loop_len + 4;

    raw[abs_section + 1] = (section[1] & 0xF0) | ((new_section_length >> 8) & 0x0F) as u8;
    raw[abs_section + 2] = (new_section_length & 0xFF) as u8;

    let mut w = abs_section + 12 + prog_info_len;
    for (st, pid) in &entries {
        raw[w] = *st;
        raw[w + 1] = 0xE0 | ((pid >> 8) & 0x1F) as u8;
        raw[w + 2] = (pid & 0xFF) as u8;
        raw[w + 3] = 0xF0;
        raw[w + 4] = 0x00;
        w += 5;
    }

    // Zero CRC (not recalculated — most players ignore it).
    raw[w] = 0x00;
    raw[w + 1] = 0x00;
    raw[w + 2] = 0x00;
    raw[w + 3] = 0x00;
    w += 4;

    // Pad remainder with 0xFF.
    while w < payload_offset + payload_len {
        raw[w] = 0xFF;
        w += 1;
    }
}

/// Run the full decryption pipeline.
pub fn run(input_path: &Path, output_path: &Path, key: &[u8; 16], iv: &[u8; 16]) -> Result<()> {
    let data = fs::read(input_path)?;
    info!(
        "Input: {} ({} bytes, {} packets)",
        input_path.display(),
        data.len(),
        data.len() / TS_PACKET_SIZE,
    );

    // First pass: parse PAT and PMT.
    let pmt_pid = find_pmt_pid(&data)?;
    let stream_map = find_pmt(&data, pmt_pid)?;

    let encrypted_pids: HashMap<u16, StreamType> = stream_map
        .into_iter()
        .filter(|(_, (_, raw))| matches!(raw, 0xDB | 0xCF | 0xC1))
        .map(|(pid, (st, _))| (pid, st))
        .collect();

    if encrypted_pids.is_empty() {
        info!("No FairPlay-encrypted streams found; copying unchanged");
        fs::write(output_path, &data)?;
        return Ok(());
    }

    // Pre-process all encrypted PIDs: concatenate ES, decrypt, re-split.
    let mut pid_pes_data: HashMap<u16, Vec<(Vec<u8>, Vec<BufferedPacket>, u8)>> = HashMap::new();
    for (&pid, &stream_type) in &encrypted_pids {
        let pes_list = preprocess_pid(&data, pid, stream_type, key, iv);
        pid_pes_data.insert(pid, pes_list);
    }

    // Build output: process packets sequentially.
    let mut output = Vec::with_capacity(data.len());
    let mut pid_pes_idx: HashMap<u16, usize> =
        encrypted_pids.keys().map(|&pid| (pid, 0)).collect();
    let mut pid_accumulating: HashMap<u16, bool> =
        encrypted_pids.keys().map(|&pid| (pid, false)).collect();

    for (_offset, pkt) in iter_packets(&data) {
        let pid = pkt.header.pid;

        if encrypted_pids.contains_key(&pid) {
            let accumulating = pid_accumulating.get_mut(&pid).unwrap();
            if pkt.header.pusi && *accumulating {
                let idx = pid_pes_idx.get_mut(&pid).unwrap();
                let pes_list = &pid_pes_data[&pid];
                if *idx < pes_list.len() {
                    let (ref pes_data, ref orig_packets, cc_start) = pes_list[*idx];
                    write_pes_to_output(&mut output, pid, pes_data, orig_packets, cc_start);
                    *idx += 1;
                }
            }
            *accumulating = true;
        } else if pid == pmt_pid {
            let mut raw = [0u8; TS_PACKET_SIZE];
            raw.copy_from_slice(pkt.raw);
            patch_pmt_packet(&mut raw, pkt.payload_offset, pkt.payload_len);
            output.extend_from_slice(&raw);
        } else {
            output.extend_from_slice(pkt.raw);
        }
    }

    // Flush remaining PES for each encrypted PID.
    for (&pid, pes_list) in &pid_pes_data {
        let idx = pid_pes_idx[&pid];
        if idx < pes_list.len() {
            let (ref pes_data, ref orig_packets, cc_start) = pes_list[idx];
            write_pes_to_output(&mut output, pid, pes_data, orig_packets, cc_start);
        }
    }

    fs::write(output_path, &output)?;
    info!(
        "Output: {} ({} bytes, {} packets)",
        output_path.display(),
        output.len(),
        output.len() / TS_PACKET_SIZE,
    );

    Ok(())
}
