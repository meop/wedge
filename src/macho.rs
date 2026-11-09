//! A stamped shim's own identity on macOS: a Mach-O UUID and a code signature identifier, both derived from a key
//! (the shim's path), then the ad-hoc signature that covers them, written as a linker writes one. The same key gives
//! the same identity whatever wedge template it is stamped from, and two keys never share one

use crate::sha256;

const MH_MAGIC_64: u32 = 0xfeed_facf;
const MH_EXECUTE: u32 = 2;
const LC_SEGMENT_64: u32 = 0x19;
const LC_UUID: u32 = 0x1b;
const LC_CODE_SIGNATURE: u32 = 0x1d;

const CSMAGIC_EMBEDDED_SIGNATURE: u32 = 0xfade_0cc0;
const CSMAGIC_CODEDIRECTORY: u32 = 0xfade_0c02;
const CSSLOT_CODEDIRECTORY: u32 = 0;
const CD_VERSION: u32 = 0x20400;
const CS_ADHOC: u32 = 0x2;
const CS_LINKER_SIGNED: u32 = 0x2_0000;
const CS_HASHTYPE_SHA256: u8 = 2;
const CS_EXECSEG_MAIN_BINARY: u64 = 1;
const CD_HEADER_SIZE: usize = 88;
const PAGE_SHIFT: u8 = 12;
const PAGE_SIZE: usize = 1 << PAGE_SHIFT;
const SEGMENT_ALIGN: u64 = 0x4000;

/// whether the bytes start as a 64-bit Mach-O
pub fn is_macho(b: &[u8]) -> bool {
    u32_at(b, 0) == Ok(MH_MAGIC_64)
}

/// the UUID a key gives: the first 16 bytes of its SHA-256, marked as a version 8 (custom) RFC 9562 UUID
pub fn uuid_for(key: &str) -> [u8; 16] {
    let mut u: [u8; 16] = sha256::digest(key.as_bytes())[..16].try_into().unwrap();
    u[6] = (u[6] & 0x0f) | 0x80;
    u[8] = (u[8] & 0x3f) | 0x80;
    u
}

/// the signing identifier: the program's name and a short hash of its key, the form a linker gives one
pub fn identifier_for(name: &str, key: &str) -> String {
    let h = sha256::digest(key.as_bytes());
    let hex: String = h[..8].iter().map(|b| format!("{b:02x}")).collect();
    format!("{name}-{hex}")
}

struct Layout {
    uuid_at: usize,
    sig_cmd_at: usize,
    linkedit_cmd_at: usize,
    linkedit_fileoff: u64,
    code_limit: usize,
    text_fileoff: u64,
    text_filesize: u64,
    executable: bool,
}

fn u32_at(b: &[u8], at: usize) -> Result<u32, String> {
    b.get(at..at + 4)
        .map(|s| u32::from_le_bytes(s.try_into().unwrap()))
        .ok_or_else(|| "Mach-O header is cut short".into())
}

fn u64_at(b: &[u8], at: usize) -> Result<u64, String> {
    b.get(at..at + 8)
        .map(|s| u64::from_le_bytes(s.try_into().unwrap()))
        .ok_or_else(|| "Mach-O header is cut short".into())
}

/// where each load command this needs sits, as far as the header goes; any of them may be missing
struct Commands {
    executable: bool,
    uuid_at: Option<usize>,
    sig_cmd_at: Option<usize>,
    linkedit_cmd_at: Option<usize>,
    text: Option<(u64, u64)>,
}

fn layout_commands(b: &[u8]) -> Result<Commands, String> {
    if u32_at(b, 0)? != MH_MAGIC_64 {
        return Err("not a 64-bit Mach-O".into());
    }
    let mut c = Commands {
        executable: u32_at(b, 12)? == MH_EXECUTE,
        uuid_at: None,
        sig_cmd_at: None,
        linkedit_cmd_at: None,
        text: None,
    };
    let ncmds = u32_at(b, 16)? as usize;
    let mut at = 32;
    for _ in 0..ncmds {
        let (cmd, size) = (u32_at(b, at)?, u32_at(b, at + 4)? as usize);
        if size < 8 {
            return Err("Mach-O load command has no size".into());
        }
        match cmd {
            LC_UUID => c.uuid_at = Some(at + 8),
            LC_CODE_SIGNATURE => c.sig_cmd_at = Some(at),
            LC_SEGMENT_64 => match b.get(at + 8..at + 24) {
                Some(name) if name.starts_with(b"__LINKEDIT\0") => c.linkedit_cmd_at = Some(at),
                Some(name) if name.starts_with(b"__TEXT\0") => {
                    c.text = Some((u64_at(b, at + 40)?, u64_at(b, at + 48)?))
                }
                _ => {}
            },
            _ => {}
        }
        at += size;
    }
    Ok(c)
}

fn layout(b: &[u8]) -> Result<Layout, String> {
    let c = layout_commands(b)?;
    let sig_cmd_at = c
        .sig_cmd_at
        .ok_or("Mach-O has no code signature to replace")?;
    let linkedit_cmd_at = c
        .linkedit_cmd_at
        .ok_or("Mach-O has no __LINKEDIT segment")?;
    let (text_fileoff, text_filesize) = c.text.ok_or("Mach-O has no __TEXT segment")?;
    let code_limit = u32_at(b, sig_cmd_at + 8)? as usize;
    let linkedit_fileoff = u64_at(b, linkedit_cmd_at + 40)?;
    if code_limit > b.len() || (code_limit as u64) < linkedit_fileoff {
        return Err("Mach-O code signature is not inside __LINKEDIT".into());
    }
    Ok(Layout {
        uuid_at: c.uuid_at.ok_or("Mach-O has no UUID")?,
        sig_cmd_at,
        linkedit_cmd_at,
        linkedit_fileoff,
        code_limit,
        text_fileoff,
        text_filesize,
        executable: c.executable,
    })
}

fn round_up(n: u64, to: u64) -> u64 {
    n.div_ceil(to) * to
}

/// where the code signature starts, read from a Mach-O's header and load commands; what precedes it is signed
pub fn code_signature_offset(header: &[u8]) -> Option<usize> {
    let l = layout_commands(header).ok()?;
    Some(u32_at(header, l.sig_cmd_at? + 8).ok()? as usize)
}

/// a template with its UUID, identifier and ad-hoc signature replaced by the ones `key` gives, and `trailer` placed
/// right before the signature, so the signature covers it and the file still ends with the signature, as macOS
/// requires of a signed program. whatever followed the template's signature is left out
pub fn restamp(template: &[u8], key: &str, name: &str, trailer: &[u8]) -> Result<Vec<u8>, String> {
    let l = layout(template)?;
    let ident = identifier_for(name, key);
    let code_limit = round_up((l.code_limit + trailer.len()) as u64, 16) as usize;
    let n_slots = code_limit.div_ceil(PAGE_SIZE);
    let hash_offset = CD_HEADER_SIZE + ident.len() + 1;
    let cd_len = hash_offset + n_slots * 32;
    let blob_len = 12 + 8 + cd_len;
    let sig_size = round_up(blob_len as u64, 16) as usize;

    let mut out = template[..l.code_limit].to_vec();
    out.resize(code_limit - trailer.len(), 0);
    out.extend_from_slice(trailer);
    out[l.uuid_at..l.uuid_at + 16].copy_from_slice(&uuid_for(key));
    out[l.sig_cmd_at + 8..l.sig_cmd_at + 12].copy_from_slice(&(code_limit as u32).to_le_bytes());
    out[l.sig_cmd_at + 12..l.sig_cmd_at + 16].copy_from_slice(&(sig_size as u32).to_le_bytes());
    let linkedit_filesize = code_limit as u64 + sig_size as u64 - l.linkedit_fileoff;
    out[l.linkedit_cmd_at + 48..l.linkedit_cmd_at + 56]
        .copy_from_slice(&linkedit_filesize.to_le_bytes());
    out[l.linkedit_cmd_at + 32..l.linkedit_cmd_at + 40]
        .copy_from_slice(&round_up(linkedit_filesize, SEGMENT_ALIGN).to_le_bytes());

    let mut sig = Vec::with_capacity(sig_size);
    sig.extend(CSMAGIC_EMBEDDED_SIGNATURE.to_be_bytes());
    sig.extend((blob_len as u32).to_be_bytes());
    sig.extend(1u32.to_be_bytes());
    sig.extend(CSSLOT_CODEDIRECTORY.to_be_bytes());
    sig.extend(20u32.to_be_bytes());

    sig.extend(CSMAGIC_CODEDIRECTORY.to_be_bytes());
    sig.extend((cd_len as u32).to_be_bytes());
    sig.extend(CD_VERSION.to_be_bytes());
    sig.extend((CS_ADHOC | CS_LINKER_SIGNED).to_be_bytes());
    sig.extend((hash_offset as u32).to_be_bytes());
    sig.extend((CD_HEADER_SIZE as u32).to_be_bytes());
    sig.extend(0u32.to_be_bytes()); // special slots
    sig.extend((n_slots as u32).to_be_bytes());
    sig.extend((code_limit as u32).to_be_bytes());
    sig.extend([32, CS_HASHTYPE_SHA256, 0, PAGE_SHIFT]);
    sig.extend([0u8; 16]); // spare2, scatter offset, team offset, spare3
    sig.extend(0u64.to_be_bytes()); // 64-bit code limit, unused below 4 GiB
    sig.extend(l.text_fileoff.to_be_bytes());
    sig.extend(l.text_filesize.to_be_bytes());
    let exec_flags = if l.executable {
        CS_EXECSEG_MAIN_BINARY
    } else {
        0
    };
    sig.extend(exec_flags.to_be_bytes());
    sig.extend(ident.as_bytes());
    sig.push(0);
    for page in out.chunks(PAGE_SIZE) {
        sig.extend(sha256::digest(page));
    }
    sig.resize(sig_size, 0);

    out.extend(sig);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// a minimal executable: __TEXT, __LINKEDIT, a UUID and a code signature, the signature `old_sig` bytes long
    fn template(old_sig: usize, fill: u8) -> Vec<u8> {
        let mut b = vec![0u8; 0x4000];
        let put32 =
            |b: &mut Vec<u8>, at: usize, v: u32| b[at..at + 4].copy_from_slice(&v.to_le_bytes());
        let put64 =
            |b: &mut Vec<u8>, at: usize, v: u64| b[at..at + 8].copy_from_slice(&v.to_le_bytes());
        put32(&mut b, 0, MH_MAGIC_64);
        put32(&mut b, 12, MH_EXECUTE);
        put32(&mut b, 16, 4);
        let mut at = 32;
        for (name, fileoff, filesize) in [
            (&b"__TEXT"[..], 0u64, 0x4000u64),
            (b"__LINKEDIT", 0x4000, 0),
        ] {
            put32(&mut b, at, LC_SEGMENT_64);
            put32(&mut b, at + 4, 72);
            b[at + 8..at + 8 + name.len()].copy_from_slice(name);
            put64(&mut b, at + 40, fileoff);
            put64(&mut b, at + 48, filesize);
            at += 72;
        }
        put32(&mut b, at, LC_UUID);
        put32(&mut b, at + 4, 24);
        b[at + 8..at + 24].fill(0xaa);
        at += 24;
        put32(&mut b, at, LC_CODE_SIGNATURE);
        put32(&mut b, at + 4, 16);
        put32(&mut b, at + 8, 0x4100);
        put32(&mut b, at + 12, old_sig as u32);
        b[0x200..0x4000].fill(fill);
        b.resize(0x4100, 0x11);
        b.resize(0x4100 + old_sig, 0xee);
        b
    }

    fn sig_of(out: &[u8]) -> (usize, usize, &[u8]) {
        let l = layout(out).unwrap();
        let size = u32_at(out, l.sig_cmd_at + 12).unwrap() as usize;
        (l.code_limit, size, &out[l.code_limit..])
    }

    fn be32(b: &[u8], at: usize) -> u32 {
        u32::from_be_bytes(b[at..at + 4].try_into().unwrap())
    }

    #[test]
    fn a_key_gives_one_uuid_and_two_keys_two() {
        let a = uuid_for("/Users/u/.ghpm/bin/delishd");
        assert_eq!(a, uuid_for("/Users/u/.ghpm/bin/delishd"));
        assert_ne!(a, uuid_for("/Users/u/.ghpm/bin/nu"));
        assert_eq!(a[6] >> 4, 8);
        assert_eq!(a[8] >> 6, 0b10);
    }

    #[test]
    fn the_identity_follows_the_key_not_the_template_bytes_around_it() {
        let key = "/Users/u/.ghpm/bin/delishd";
        let one = restamp(&template(0x200, 0x22), key, "delishd", b"").unwrap();
        let two = restamp(&template(0x80, 0x33), key, "delishd", b"").unwrap();
        let l1 = layout(&one).unwrap();
        let l2 = layout(&two).unwrap();
        assert_eq!(one[l1.uuid_at..l1.uuid_at + 16], uuid_for(key));
        assert_eq!(two[l2.uuid_at..l2.uuid_at + 16], uuid_for(key));
        let ident = identifier_for("delishd", key);
        for out in [&one, &two] {
            let (_, _, sig) = sig_of(out);
            assert_eq!(&sig[20 + 88..20 + 88 + ident.len()], ident.as_bytes());
        }
    }

    #[test]
    fn the_signature_hashes_every_page_up_to_it_and_ends_the_file_and_linkedit() {
        let out = restamp(&template(0x200, 0x22), "/k", "wedge", b"").unwrap();
        let (limit, size, sig) = sig_of(&out);
        assert_eq!(out.len(), limit + size);
        assert_eq!(size % 16, 0);
        assert_eq!(be32(sig, 0), CSMAGIC_EMBEDDED_SIGNATURE);
        let cd = &sig[20..];
        assert_eq!(be32(cd, 0), CSMAGIC_CODEDIRECTORY);
        assert_eq!(be32(cd, 12), CS_ADHOC | CS_LINKER_SIGNED);
        assert_eq!(be32(cd, 32) as usize, limit);
        let (hash_offset, slots) = (be32(cd, 16) as usize, be32(cd, 28) as usize);
        assert_eq!(slots, limit.div_ceil(PAGE_SIZE));
        for (i, page) in out[..limit].chunks(PAGE_SIZE).enumerate() {
            let at = hash_offset + i * 32;
            assert_eq!(cd[at..at + 32], sha256::digest(page), "page {i}");
        }
        let l = layout(&out).unwrap();
        let filesize = u64_at(&out, l.linkedit_cmd_at + 48).unwrap();
        assert_eq!(l.linkedit_fileoff + filesize, out.len() as u64);
        assert_eq!(
            u64_at(&out, l.linkedit_cmd_at + 32).unwrap() % SEGMENT_ALIGN,
            0
        );
    }

    #[test]
    fn the_trailer_ends_right_before_the_signature_which_covers_it() {
        let mut t = template(0x200, 0x22);
        t.extend(b"/old/target\x0b\0\0\0SHIM");
        let trailer = b"/new/target\x0b\0\0\0SHIM";
        let out = restamp(&t, "/k", "wedge", trailer).unwrap();
        let (limit, size, sig) = sig_of(&out);
        assert_eq!(out.len(), limit + size);
        assert_eq!(limit % 16, 0);
        assert_eq!(&out[limit - trailer.len()..limit], trailer);
        assert_eq!(code_signature_offset(&out[..0x200]), Some(limit));
        let cd = &sig[20..];
        assert_eq!(be32(cd, 32) as usize, limit);
        let last = (limit - 1) / PAGE_SIZE;
        let at = be32(cd, 16) as usize + last * 32;
        assert_eq!(
            cd[at..at + 32],
            sha256::digest(&out[last * PAGE_SIZE..limit])
        );
        assert!(!out.windows(11).any(|w| w == b"/old/target"));
    }

    #[test]
    fn a_mach_o_is_told_from_other_files() {
        assert!(is_macho(&template(0x200, 0x22)));
        assert!(!is_macho(b"\x7fELF\x02\x01\x01\0"));
        assert!(!is_macho(b"template"));
    }

    #[test]
    fn anything_but_a_signed_64_bit_mach_o_is_refused() {
        assert!(restamp(b"\x7fELF\x02\x01\x01\0", "/k", "wedge", b"").is_err());
        let mut unsigned = template(0x200, 0x22);
        unsigned[16..20].copy_from_slice(&3u32.to_le_bytes());
        assert!(restamp(&unsigned, "/k", "wedge", b"").is_err());
    }
}
