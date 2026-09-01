//! Code pages and locales, as far as a C runtime starting up asks about them.
//!
//! The process runs with the ANSI code page set to UTF-8 (65001), which is a
//! configuration Windows 10 offers and every current runtime accepts; it makes
//! `MultiByteToWideChar` and `WideCharToMultiByte` plain conversions between
//! UTF-8 and UTF-16 and leaves nothing to a table. What each returns and how
//! each fails follows Wine's `dlls/kernelbase/locale.c`: a zero-sized output
//! asks how much is needed, too small an output is `ERROR_INSUFFICIENT_BUFFER`,
//! and malformed input is replaced with U+FFFD unless the caller asked to be
//! told, in which case it is `ERROR_NO_UNICODE_TRANSLATION`.
//!
//! The locale is en-US and only what it needs is answered: character classes
//! for `GetStringTypeW`, upper and lower case for `LCMapStringW`, and an
//! ordinal comparison for `CompareStringW`, which is what the invariant locale
//! specifies. Linguistic tables are not here, and calls that need them say so.

use alloc::vec::Vec;

use super::{Call, Dispatch, ERROR_INSUFFICIENT_BUFFER, ERROR_INVALID_PARAMETER, FALSE, TRUE};

const ERROR_INVALID_FLAGS: u32 = 1004;
const ERROR_NO_UNICODE_TRANSLATION: u32 = 1113;

// Code page selectors (`winnls.h`).
const CP_ACP: u32 = 0;
const CP_OEMCP: u32 = 1;
const CP_MACCP: u32 = 2;
const CP_THREAD_ACP: u32 = 3;
const CP_UTF8: u32 = 65001;

/// The process's ANSI and OEM code page.
pub const ACP: u32 = CP_UTF8;

const MB_ERR_INVALID_CHARS: u32 = 0x8;
const MB_FLAGS: u32 = 0x1 | 0x2 | 0x4 | MB_ERR_INVALID_CHARS; // PRECOMPOSED, COMPOSITE, USEGLYPHCHARS
const WC_ERR_INVALID_CHARS: u32 = 0x80;
const WC_FLAGS: u32 = 0x10 | 0x20 | 0x40 | WC_ERR_INVALID_CHARS | 0x200 | 0x400;

// CT_CTYPE1 bits (`winnls.h`).
const C1_UPPER: u16 = 0x0001;
const C1_LOWER: u16 = 0x0002;
const C1_DIGIT: u16 = 0x0004;
const C1_SPACE: u16 = 0x0008;
const C1_PUNCT: u16 = 0x0010;
const C1_CNTRL: u16 = 0x0020;
const C1_BLANK: u16 = 0x0040;
const C1_XDIGIT: u16 = 0x0080;
const C1_ALPHA: u16 = 0x0100;
const C1_DEFINED: u16 = 0x0200;
const CT_CTYPE1: u32 = 1;

const LCMAP_LOWERCASE: u32 = 0x100;
const LCMAP_UPPERCASE: u32 = 0x200;
const LCMAP_LINGUISTIC_CASING: u32 = 0x0100_0000;

const NORM_IGNORECASE: u32 = 0x1;
const CSTR_LESS_THAN: usize = 1;
const CSTR_EQUAL: usize = 2;
const CSTR_GREATER_THAN: usize = 3;

/// The locale every answer here is for: en-US.
pub const USER_LCID: u32 = 0x0409;

/// Whether `codepage` names the one this process has, under any of its names.
fn is_ours(codepage: u32) -> bool {
    matches!(codepage, CP_ACP | CP_OEMCP | CP_THREAD_ACP | CP_UTF8)
}

pub fn is_valid_code_page(c: &mut Call<'_>) -> Dispatch {
    // The selectors are not code pages, as Wine answers too.
    let valid = match c.arg(0) as u32 {
        CP_ACP | CP_OEMCP | CP_MACCP | CP_THREAD_ACP => false,
        cp => cp == CP_UTF8,
    };
    c.finish(valid as usize)
}

/// GetCPInfo(CodePage, lpCPInfo): CPINFO { MaxCharSize, DefaultChar[2],
/// LeadByte[12] }. UTF-8 has no lead bytes and a default of `?`.
pub fn get_cp_info(c: &mut Call<'_>) -> Dispatch {
    let (codepage, out) = (c.arg(0) as u32, c.arg(1));
    if out == 0 || !is_ours(codepage) {
        return c.fail(ERROR_INVALID_PARAMETER, FALSE);
    }
    let mut info = [0u8; 20];
    info[..4].copy_from_slice(&4u32.to_le_bytes());
    info[4] = b'?';
    if !c.write(out, &info) {
        return c.fail(ERROR_INVALID_PARAMETER, FALSE);
    }
    c.finish(TRUE)
}

/// MultiByteToWideChar(CodePage, dwFlags, lpMultiByteStr, cbMultiByte,
/// lpWideCharStr, cchWideChar).
pub fn multi_byte_to_wide_char(c: &mut Call<'_>) -> Dispatch {
    let (codepage, flags, src, srclen, dst, dstlen) = (
        c.arg(0) as u32,
        c.arg(1) as u32,
        c.arg(2),
        c.arg(3) as i32,
        c.arg(4),
        c.arg(5) as i32,
    );
    if src == 0 || srclen == 0 || (dst == 0 && dstlen != 0) || dstlen < 0 || !is_ours(codepage) {
        return c.fail(ERROR_INVALID_PARAMETER, 0);
    }
    if flags & !MB_FLAGS != 0 {
        return c.fail(ERROR_INVALID_FLAGS, 0);
    }
    // A negative length means "up to and including the terminator".
    let Some(bytes) = (if srclen < 0 {
        c.read_cstr(src)
    } else {
        c.read_bytes(src, srclen as usize)
    }) else {
        return c.fail(ERROR_INVALID_PARAMETER, 0);
    };
    let mut units: Vec<u16> = Vec::new();
    let mut malformed = false;
    for chunk in bytes.utf8_chunks() {
        for ch in chunk.valid().chars() {
            let mut buf = [0u16; 2];
            units.extend_from_slice(ch.encode_utf16(&mut buf));
        }
        if !chunk.invalid().is_empty() {
            malformed = true;
            units.push(0xFFFD);
        }
    }
    if malformed && flags & MB_ERR_INVALID_CHARS != 0 {
        return c.fail(ERROR_NO_UNICODE_TRANSLATION, 0);
    }
    if dstlen == 0 {
        return c.finish(units.len());
    }
    if units.len() > dstlen as usize {
        return c.fail(ERROR_INSUFFICIENT_BUFFER, 0);
    }
    let out: Vec<u8> = units.iter().flat_map(|u| u.to_le_bytes()).collect();
    if !c.write(dst, &out) {
        return c.fail(ERROR_INVALID_PARAMETER, 0);
    }
    c.finish(units.len())
}

/// WideCharToMultiByte(CodePage, dwFlags, lpWideCharStr, cchWideChar,
/// lpMultiByteStr, cbMultiByte, lpDefaultChar, lpUsedDefaultChar).
pub fn wide_char_to_multi_byte(c: &mut Call<'_>) -> Dispatch {
    let (codepage, flags, src, srclen, dst, dstlen, used) = (
        c.arg(0) as u32,
        c.arg(1) as u32,
        c.arg(2),
        c.arg(3) as i32,
        c.arg(4),
        c.arg(5) as i32,
        c.arg(7),
    );
    if src == 0 || srclen == 0 || (dst == 0 && dstlen != 0) || dstlen < 0 || !is_ours(codepage) {
        return c.fail(ERROR_INVALID_PARAMETER, 0);
    }
    if flags & !WC_FLAGS != 0 {
        return c.fail(ERROR_INVALID_FLAGS, 0);
    }
    // UTF-8 never falls back to a default character, so the flag a caller
    // asked for is cleared before anything else, as Wine clears it.
    if used != 0 {
        c.write_u32(used, 0);
    }
    let Some(units) = (if srclen < 0 {
        c.read_wstr(src)
    } else {
        c.read_wide_n(src, srclen as usize)
    }) else {
        return c.fail(ERROR_INVALID_PARAMETER, 0);
    };
    let mut out: Vec<u8> = Vec::new();
    let mut malformed = false;
    for item in char::decode_utf16(units.iter().copied()) {
        let ch = match item {
            Ok(ch) => ch,
            Err(_) => {
                malformed = true;
                '\u{FFFD}'
            }
        };
        let mut buf = [0u8; 4];
        out.extend_from_slice(ch.encode_utf8(&mut buf).as_bytes());
    }
    if malformed && flags & WC_ERR_INVALID_CHARS != 0 {
        return c.fail(ERROR_NO_UNICODE_TRANSLATION, 0);
    }
    if dstlen == 0 {
        return c.finish(out.len());
    }
    if out.len() > dstlen as usize {
        return c.fail(ERROR_INSUFFICIENT_BUFFER, 0);
    }
    if !c.write(dst, &out) {
        return c.fail(ERROR_INVALID_PARAMETER, 0);
    }
    c.finish(out.len())
}

/// The CT_CTYPE1 class of one UTF-16 unit.
fn ctype1(unit: u16) -> u16 {
    let Some(ch) = char::from_u32(u32::from(unit)) else {
        // A lone surrogate is a defined code unit and nothing else.
        return C1_DEFINED;
    };
    let mut bits = C1_DEFINED;
    if ch.is_uppercase() {
        bits |= C1_UPPER;
    }
    if ch.is_lowercase() {
        bits |= C1_LOWER;
    }
    if ch.is_alphabetic() {
        bits |= C1_ALPHA;
    }
    if ch.is_ascii_digit() {
        bits |= C1_DIGIT;
    }
    if ch.is_ascii_hexdigit() {
        bits |= C1_XDIGIT;
    }
    if ch.is_whitespace() {
        bits |= C1_SPACE;
    }
    if ch == ' ' || ch == '\t' {
        bits |= C1_BLANK;
    }
    if ch.is_control() {
        bits |= C1_CNTRL;
    }
    if ch.is_ascii_punctuation() {
        bits |= C1_PUNCT;
    }
    bits
}

/// GetStringTypeW(dwInfoType, lpSrcStr, cchSrc, lpCharType): CT_CTYPE1 only;
/// the other two tables are not here.
pub fn get_string_type(c: &mut Call<'_>) -> Dispatch {
    let (kind, src, count, out) = (c.arg(0) as u32, c.arg(1), c.arg(2) as i32, c.arg(3));
    if src == 0 || kind != CT_CTYPE1 {
        return c.fail(ERROR_INVALID_PARAMETER, FALSE);
    }
    let Some(units) = (if count == -1 {
        c.read_wstr(src).map(|mut u| {
            u.push(0);
            u
        })
    } else {
        c.read_wide_n(src, count as usize)
    }) else {
        return c.fail(ERROR_INVALID_PARAMETER, FALSE);
    };
    let classes: Vec<u8> = units
        .iter()
        .flat_map(|u| ctype1(*u).to_le_bytes())
        .collect();
    if !c.write(out, &classes) {
        return c.fail(ERROR_INVALID_PARAMETER, FALSE);
    }
    c.finish(TRUE)
}

/// LCMapStringW(Locale, dwMapFlags, lpSrcStr, cchSrc, lpDestStr, cchDest):
/// upper and lower case, one unit to one unit, which is all a runtime asks of
/// the invariant locale at startup.
pub fn lc_map_string(c: &mut Call<'_>) -> Dispatch {
    lc_map(
        c,
        c.arg(1) as u32,
        c.arg(2),
        c.arg(3) as i32,
        c.arg(4),
        c.arg(5) as i32,
    )
}

/// LCMapStringEx(locale, flags, src, srclen, dst, dstlen, ...): the same
/// mapping, with the locale named rather than an LCID; the arguments are
/// shifted by one.
pub fn lc_map_string_ex(c: &mut Call<'_>) -> Dispatch {
    lc_map(
        c,
        c.arg(1) as u32,
        c.arg(2),
        c.arg(3) as i32,
        c.arg(4),
        c.arg(5) as i32,
    )
}

fn lc_map(
    c: &mut Call<'_>,
    flags: u32,
    src: usize,
    srclen: i32,
    dst: usize,
    dstlen: i32,
) -> Dispatch {
    let casing = flags & !LCMAP_LINGUISTIC_CASING;
    if casing != LCMAP_UPPERCASE && casing != LCMAP_LOWERCASE {
        return c.fail(ERROR_INVALID_FLAGS, 0);
    }
    if src == 0 || srclen == 0 || dstlen < 0 {
        return c.fail(ERROR_INVALID_PARAMETER, 0);
    }
    let Some(units) = (if srclen < 0 {
        c.read_wstr(src).map(|mut u| {
            u.push(0);
            u
        })
    } else {
        c.read_wide_n(src, srclen as usize)
    }) else {
        return c.fail(ERROR_INVALID_PARAMETER, 0);
    };
    let mapped: Vec<u16> = units
        .iter()
        .map(|unit| match char::from_u32(u32::from(*unit)) {
            Some(ch) => {
                let mut it = if casing == LCMAP_UPPERCASE {
                    ch.to_uppercase().next()
                } else {
                    ch.to_lowercase().next()
                };
                match it.take().and_then(|m| u16::try_from(u32::from(m)).ok()) {
                    Some(m) => m,
                    None => *unit,
                }
            }
            None => *unit,
        })
        .collect();
    if dstlen == 0 {
        return c.finish(mapped.len());
    }
    if mapped.len() > dstlen as usize {
        return c.fail(ERROR_INSUFFICIENT_BUFFER, 0);
    }
    let out: Vec<u8> = mapped.iter().flat_map(|u| u.to_le_bytes()).collect();
    if !c.write(dst, &out) {
        return c.fail(ERROR_INVALID_PARAMETER, 0);
    }
    c.finish(mapped.len())
}

/// CompareStringW(Locale, dwCmpFlags, lpString1, cchCount1, lpString2,
/// cchCount2): the ordinal order the invariant locale defines, folding case
/// when asked.
pub fn compare_string(c: &mut Call<'_>) -> Dispatch {
    let (flags, s1, n1, s2, n2) = (
        c.arg(1) as u32,
        c.arg(2),
        c.arg(3) as i32,
        c.arg(4),
        c.arg(5) as i32,
    );
    let read = |c: &Call<'_>, at: usize, n: i32| {
        if n < 0 {
            c.read_wstr(at)
        } else {
            c.read_wide_n(at, n as usize)
        }
    };
    let (Some(a), Some(b)) = (read(c, s1, n1), read(c, s2, n2)) else {
        return c.fail(ERROR_INVALID_PARAMETER, 0);
    };
    let fold = |u: &u16| -> u32 {
        if flags & NORM_IGNORECASE != 0 {
            char::from_u32(u32::from(*u))
                .and_then(|ch| ch.to_lowercase().next())
                .map_or(u32::from(*u), u32::from)
        } else {
            u32::from(*u)
        }
    };
    let ordering = a.iter().map(fold).cmp(b.iter().map(fold));
    c.finish(match ordering {
        core::cmp::Ordering::Less => CSTR_LESS_THAN,
        core::cmp::Ordering::Equal => CSTR_EQUAL,
        core::cmp::Ordering::Greater => CSTR_GREATER_THAN,
    })
}

/// IsValidLocale(Locale, dwFlags): the one locale here, under each of the
/// names it goes by.
pub fn is_valid_locale(c: &mut Call<'_>) -> Dispatch {
    // LOCALE_USER_DEFAULT, LOCALE_SYSTEM_DEFAULT, LOCALE_INVARIANT, en-US.
    let valid = matches!(c.arg(0) as u32, 0x0400 | 0x0800 | 0x007F | USER_LCID);
    c.finish(valid as usize)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn character_classes_match_the_c_runtime_tables() {
        assert_eq!(
            ctype1(u16::from(b'A')),
            C1_DEFINED | C1_UPPER | C1_ALPHA | C1_XDIGIT
        );
        assert_eq!(ctype1(u16::from(b'z')), C1_DEFINED | C1_LOWER | C1_ALPHA);
        assert_eq!(ctype1(u16::from(b'7')), C1_DEFINED | C1_DIGIT | C1_XDIGIT);
        assert_eq!(ctype1(u16::from(b' ')), C1_DEFINED | C1_SPACE | C1_BLANK);
        assert_eq!(ctype1(u16::from(b'\n')), C1_DEFINED | C1_SPACE | C1_CNTRL);
        assert_eq!(ctype1(u16::from(b'!')), C1_DEFINED | C1_PUNCT);
    }
}

// The few LCTYPEs a C runtime reads at startup, answered for en-US
// (`winnls.h`); anything else is an empty string, which a caller treats as
// "not available" rather than a failure.
const LOCALE_ILANGUAGE: u32 = 0x1;
const LOCALE_SLANGUAGE: u32 = 0x2;
const LOCALE_SISO639LANGNAME: u32 = 0x59;
const LOCALE_SISO3166CTRYNAME: u32 = 0x5A;
const LOCALE_IDEFAULTANSICODEPAGE: u32 = 0x1004;
const LOCALE_IDEFAULTCODEPAGE: u32 = 0xB;
const LOCALE_SNAME: u32 = 0x5C;
const LOCALE_RETURN_NUMBER: u32 = 0x2000_0000;

/// GetLocaleInfoW(lcid, lctype, buffer, len): a short answer for the locale
/// this process runs as. `len` of zero asks for the length needed.
pub fn get_locale_info_w(c: &mut Call<'_>) -> Dispatch {
    let (lctype, buffer, len) = (c.arg(1) as u32, c.arg(2), c.arg(3) as i32);
    if len < 0 {
        return c.fail(ERROR_INVALID_PARAMETER, 0);
    }
    // LOCALE_RETURN_NUMBER wants the value as a DWORD in the buffer, not text.
    if lctype & LOCALE_RETURN_NUMBER != 0 {
        let value: u32 = match lctype & !LOCALE_RETURN_NUMBER {
            LOCALE_IDEFAULTANSICODEPAGE | LOCALE_IDEFAULTCODEPAGE => ACP,
            LOCALE_ILANGUAGE => USER_LCID,
            _ => 0,
        };
        if len < 2 {
            return c.finish(2);
        }
        if !c.write(buffer, &value.to_le_bytes()) {
            return c.fail(ERROR_INVALID_PARAMETER, 0);
        }
        return c.finish(2);
    }
    let text = match lctype & 0xFFFF {
        LOCALE_SISO639LANGNAME => "en",
        LOCALE_SISO3166CTRYNAME => "US",
        LOCALE_SNAME => "en-US",
        LOCALE_SLANGUAGE => "English (United States)",
        _ => "",
    };
    let units: alloc::vec::Vec<u16> = text.encode_utf16().collect();
    if len == 0 {
        return c.finish(units.len() + 1);
    }
    if units.len() + 1 > len as usize {
        return c.fail(ERROR_INSUFFICIENT_BUFFER, 0);
    }
    let mut out: alloc::vec::Vec<u8> = units.iter().flat_map(|u| u.to_le_bytes()).collect();
    out.extend_from_slice(&[0, 0]);
    if !c.write(buffer, &out) {
        return c.fail(ERROR_INVALID_PARAMETER, 0);
    }
    c.finish(units.len() + 1)
}
