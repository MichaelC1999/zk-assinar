//! Minimal BER/DER reader: tag, length (incl. indefinite), value slice.

#[derive(Clone, Copy, Debug)]
pub struct Tlv<'a> {
    pub tag: u8,
    /// Value bytes (for indefinite length: up to, not including, the end-of-contents marker).
    pub val: &'a [u8],
    /// Whole encoding, header included.
    pub raw: &'a [u8],
}

pub fn read(d: &[u8]) -> Result<Tlv<'_>, &'static str> {
    if d.len() < 2 {
        return Err("short");
    }
    let tag = d[0];
    if tag & 0x1f == 0x1f {
        return Err("high tag");
    }
    let l0 = d[1];
    if l0 == 0x80 {
        if tag & 0x20 == 0 {
            return Err("indefinite primitive");
        }
        let mut p = 2;
        loop {
            if d.len() < p + 2 {
                return Err("unterminated");
            }
            if d[p] == 0 && d[p + 1] == 0 {
                return Ok(Tlv { tag, val: &d[2..p], raw: &d[..p + 2] });
            }
            p += read(&d[p..])?.raw.len();
        }
    }
    let (len, hdr) = if l0 < 0x80 {
        (l0 as usize, 2)
    } else {
        let n = (l0 & 0x7f) as usize;
        if n > 4 || d.len() < 2 + n {
            return Err("bad length");
        }
        (d[2..2 + n].iter().fold(0usize, |a, &b| (a << 8) | b as usize), 2 + n)
    };
    if d.len() < hdr + len {
        return Err("truncated");
    }
    Ok(Tlv { tag, val: &d[hdr..hdr + len], raw: &d[..hdr + len] })
}

/// Children of a constructed value.
pub fn children(mut d: &[u8]) -> Result<Vec<Tlv<'_>>, &'static str> {
    let mut v = Vec::new();
    while !d.is_empty() {
        let t = read(d)?;
        d = &d[t.raw.len()..];
        v.push(t);
    }
    Ok(v)
}
