//! Readable text of a LevelDB table file (`.ldb`). Chromium's Local Storage moves
//! records from its `.log` file into these tables, whose blocks are often
//! Snappy-compressed, so a byte search of the raw file can miss `k2f.agent.state`.

/// The keys and values of every data block, one record per line, or None when the
/// file is not a LevelDB table. The files come from a compromised machine, so every
/// length is checked and the output is capped.
pub fn readable(file: &[u8]) -> Option<Vec<u8>> {
    const MAGIC: u64 = 0xdb47_7524_8b80_fb57;
    let footer = file.get(file.len().checked_sub(48)?..)?;
    if u64::from_le_bytes(footer[40..].try_into().ok()?) != MAGIC {
        return None;
    }
    let mut pos = 0;
    // The metaindex handle comes first; only the index handle is needed.
    varint(footer, &mut pos)?;
    varint(footer, &mut pos)?;
    let index = block(file, varint(footer, &mut pos)?, varint(footer, &mut pos)?)?;
    let mut out = Vec::new();
    for (_, handle) in entries(&index) {
        let mut p = 0;
        let (Some(offset), Some(size)) = (varint(handle, &mut p), varint(handle, &mut p)) else {
            continue;
        };
        let Some(data) = block(file, offset, size) else {
            continue;
        };
        for (key, value) in entries(&data) {
            if out.len() > LIMIT {
                return Some(out);
            }
            out.extend_from_slice(&key);
            out.push(b'=');
            out.extend_from_slice(value);
            out.push(b'\n');
        }
    }
    Some(out)
}

/// Ceiling for one table's decompressed text and for one decompressed block.
const LIMIT: usize = 64 << 20;

/// A block and its 5-byte trailer: 1 byte of compression type, 4 bytes of CRC.
fn block(file: &[u8], offset: u64, size: u64) -> Option<Vec<u8>> {
    let start = usize::try_from(offset).ok()?;
    let end = start.checked_add(usize::try_from(size).ok()?)?;
    let raw = file.get(start..end)?;
    match file.get(end)? {
        0 => Some(raw.to_vec()),
        1 => snappy(raw),
        _ => None,
    }
}

/// The records of a block. Keys share a prefix with the key before them, so each
/// key is rebuilt from the previous one.
fn entries(block: &[u8]) -> Vec<(Vec<u8>, &[u8])> {
    let mut out = Vec::new();
    let Some(count) = block.len().checked_sub(4).and_then(|i| block.get(i..)).map(|b| u32::from_le_bytes(b.try_into().unwrap())) else {
        return out;
    };
    let Some(end) = (count as usize).checked_mul(4).and_then(|r| block.len().checked_sub(4 + r)) else {
        return out;
    };
    let body = &block[..end];
    let (mut pos, mut key) = (0, Vec::new());
    while pos < body.len() {
        let (Some(shared), Some(own), Some(len)) = (varint(body, &mut pos), varint(body, &mut pos), varint(body, &mut pos)) else {
            break;
        };
        let (Ok(shared), Ok(own), Ok(len)) = (usize::try_from(shared), usize::try_from(own), usize::try_from(len)) else {
            break;
        };
        let (Some(delta), Some(value)) = (body.get(pos..pos.saturating_add(own)), body.get(pos.saturating_add(own)..pos.saturating_add(own).saturating_add(len))) else {
            break;
        };
        if shared > key.len() {
            break;
        }
        key.truncate(shared);
        key.extend_from_slice(delta);
        out.push((key.clone(), value));
        pos += own + len;
    }
    out
}

fn varint(buf: &[u8], pos: &mut usize) -> Option<u64> {
    let mut value = 0u64;
    for shift in (0..64).step_by(7) {
        let byte = *buf.get(*pos)?;
        *pos += 1;
        value |= u64::from(byte & 0x7f) << shift;
        if byte < 0x80 {
            return Some(value);
        }
    }
    None
}

/// Raw Snappy (the block format LevelDB uses, not the framed one).
fn snappy(input: &[u8]) -> Option<Vec<u8>> {
    let mut pos = 0;
    let size = usize::try_from(varint(input, &mut pos)?).ok()?;
    if size > LIMIT {
        return None;
    }
    let mut out = Vec::with_capacity(size);
    while pos < input.len() {
        let tag = input[pos];
        pos += 1;
        let (len, offset) = match tag & 3 {
            0 => {
                let mut len = usize::from(tag >> 2);
                if len >= 60 {
                    let bytes = len - 59;
                    let raw = input.get(pos..pos + bytes)?;
                    len = raw.iter().rev().fold(0, |acc, b| (acc << 8) | usize::from(*b));
                    pos += bytes;
                }
                let literal = input.get(pos..pos.checked_add(len + 1)?)?;
                out.extend_from_slice(literal);
                pos += len + 1;
                continue;
            }
            1 => {
                let low = usize::from(*input.get(pos)?);
                pos += 1;
                (usize::from((tag >> 2) & 7) + 4, (usize::from(tag >> 5) << 8) | low)
            }
            2 => {
                let raw = input.get(pos..pos + 2)?;
                pos += 2;
                (usize::from(tag >> 2) + 1, usize::from(u16::from_le_bytes([raw[0], raw[1]])))
            }
            _ => {
                let raw = input.get(pos..pos + 4)?;
                pos += 4;
                (usize::from(tag >> 2) + 1, u32::from_le_bytes(raw.try_into().ok()?) as usize)
            }
        };
        if offset == 0 || offset > out.len() || out.len() + len > size {
            return None;
        }
        // Copies can overlap their own output, so they go byte by byte.
        let start = out.len() - offset;
        for i in 0..len {
            out.push(out[start + i]);
        }
    }
    (out.len() == size).then_some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn put_varint(out: &mut Vec<u8>, mut v: u64) {
        while v >= 0x80 {
            out.push(v as u8 | 0x80);
            v >>= 7;
        }
        out.push(v as u8);
    }

    /// A block with the given records, each key sharing its prefix with the one before.
    fn make_block(records: &[(&[u8], &[u8])]) -> Vec<u8> {
        let mut out = Vec::new();
        let mut prev: &[u8] = &[];
        for (key, value) in records {
            let shared = prev.iter().zip(key.iter()).take_while(|(a, b)| a == b).count();
            put_varint(&mut out, shared as u64);
            put_varint(&mut out, (key.len() - shared) as u64);
            put_varint(&mut out, value.len() as u64);
            out.extend_from_slice(&key[shared..]);
            out.extend_from_slice(value);
            prev = key;
        }
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&1u32.to_le_bytes());
        out
    }

    /// Snappy with literals only, which every decoder must accept.
    fn snappy_literal(data: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        put_varint(&mut out, data.len() as u64);
        for chunk in data.chunks(256) {
            out.push(60 << 2);
            out.push((chunk.len() - 1) as u8);
            out.extend_from_slice(chunk);
        }
        out
    }

    fn table(data: &[u8], compression: u8) -> Vec<u8> {
        let mut file = data.to_vec();
        file.push(compression);
        file.extend_from_slice(&[0; 4]);
        let mut handle = Vec::new();
        put_varint(&mut handle, 0);
        put_varint(&mut handle, data.len() as u64);
        let index = make_block(&[(b"z", &handle)]);
        let index_at = file.len();
        file.extend_from_slice(&index);
        file.push(0);
        file.extend_from_slice(&[0; 4]);
        let mut footer = Vec::new();
        put_varint(&mut footer, 0);
        put_varint(&mut footer, 0);
        put_varint(&mut footer, index_at as u64);
        put_varint(&mut footer, index.len() as u64);
        footer.resize(40, 0);
        footer.extend_from_slice(&0xdb47_7524_8b80_fb57u64.to_le_bytes());
        file.extend_from_slice(&footer);
        file
    }

    #[test]
    fn snappy_copies() {
        // "ab" as a literal, then a 1-byte-offset copy of 6 bytes from 2 back.
        let input = [8, 1 << 2, b'a', b'b', 1 | (2 << 2), 2];
        assert_eq!(snappy(&input).as_deref(), Some(&b"abababab"[..]));
        // A copy past the start of the output is rejected.
        assert_eq!(snappy(&[4, 1, 9]), None);
    }

    #[test]
    fn compressed_table_gives_back_the_key() {
        let key: &[u8] = b"_https://www.nikkelauncher.com\x00\x01k2f.agent.state";
        let data = make_block(&[(b"_https://www.nikkelauncher.com\x00\x01k2", b"x"), (key, b"{\"agent_id\":\"1\"}")]);
        assert!(!data.windows(9).any(|w| w == b"k2f.agent"), "prefix sharing hides the name in the raw block");
        for file in [table(&data, 0), table(&snappy_literal(&data), 1)] {
            let text = readable(&file).expect("table");
            assert!(text.windows(15).any(|w| w == b"k2f.agent.state"));
        }
        assert_eq!(readable(b"not a table"), None);
    }
}

