//! Strings, numbers in strings, and the one locale this library has.
//!
//! The byte-level family - `memcpy`, `strlen` and the rest - is code in the
//! synthesized library itself, because it runs over the caller's own pages
//! and nothing else. What is here needs more than a few instructions: parsing
//! a number, searching for a substring, allocating a copy, converting between
//! the multibyte and wide forms.
//!
//! There is one locale. It is named "C", and its character set is UTF-8,
//! which is what `nl_langinfo(CODESET)` reports and what the multibyte
//! conversions implement, so the name and the behaviour agree.

use alloc::vec::Vec;

use ax_abi_port::{Host, SysResult};

use crate::{
    system::{Library, PRIVATE_STRERROR, PRIVATE_TEXT_C, PRIVATE_TEXT_EMPTY, PRIVATE_TEXT_UTF8},
    user,
};

const EINVAL: i32 = 22;
const ERANGE: i32 = 34;
const EILSEQ: i32 = 92;

/// A parsed integer: its magnitude, whether a minus sign led it, how many
/// bytes it took, and whether it ran past 64 bits.
struct Parsed {
    magnitude: u64,
    negative: bool,
    used: usize,
    overflow: bool,
}

/// What `strtol` and its kin read: blanks, a sign, a base prefix, digits.
/// `used` is zero when there were no digits, which leaves the end pointer at
/// the start.
fn parse(text: &[u32], base: u32) -> Parsed {
    let mut at = 0;
    while text.get(at).is_some_and(|c| matches!(*c, 9..=13 | 32)) {
        at += 1;
    }
    let mut negative = false;
    if let Some(sign) = text
        .get(at)
        .filter(|c| **c == '-' as u32 || **c == '+' as u32)
    {
        negative = *sign == '-' as u32;
        at += 1;
    }
    let digit = |c: u32| char::from_u32(c).and_then(|c| c.to_digit(36));
    let hex_follows = |at: usize| {
        text.get(at) == Some(&('0' as u32))
            && text.get(at + 1).is_some_and(|c| *c | 0x20 == 'x' as u32)
            && text
                .get(at + 2)
                .and_then(|c| digit(*c))
                .is_some_and(|d| d < 16)
    };
    let mut base = base;
    if (base == 0 || base == 16) && hex_follows(at) {
        at += 2;
        base = 16;
    } else if base == 0 {
        base = if text.get(at) == Some(&('0' as u32)) {
            8
        } else {
            10
        };
    }
    let start = at;
    let mut magnitude = 0u64;
    let mut overflow = false;
    while let Some(value) = text.get(at).and_then(|c| digit(*c)).filter(|d| *d < base) {
        match magnitude
            .checked_mul(u64::from(base))
            .and_then(|m| m.checked_add(u64::from(value)))
        {
            Some(next) => magnitude = next,
            None => overflow = true,
        }
        at += 1;
    }
    Parsed {
        magnitude,
        negative,
        used: if at == start { 0 } else { at },
        overflow,
    }
}

fn signed(parsed: &Parsed) -> Result<i64, i64> {
    let limit = if parsed.negative {
        1u64 << 63
    } else {
        i64::MAX as u64
    };
    if parsed.overflow || parsed.magnitude > limit {
        return Err(if parsed.negative { i64::MIN } else { i64::MAX });
    }
    Ok(if parsed.negative {
        (parsed.magnitude as i64).wrapping_neg()
    } else {
        parsed.magnitude as i64
    })
}

fn base_of(base: usize) -> Result<u32, i32> {
    match base {
        0 | 2..=36 => Ok(base as u32),
        _ => Err(EINVAL),
    }
}

/// `strtol(text, end, base)`, with the range error C asks for: the nearest
/// limit is returned and `errno` says so.
pub fn strtol(host: &dyn Host, errno: usize, a: &[usize; 6], unsigned: bool) -> SysResult {
    let text: Vec<u32> = user::cstr(host, a[0])?.into_iter().map(u32::from).collect();
    let parsed = parse(&text, base_of(a[2])?);
    if a[1] != 0 {
        user::put_u64(host, a[1], (a[0] + parsed.used) as u64)?;
    }
    number(host, errno, &parsed, unsigned)
}

/// `wcstol(text, end, base)`.
pub fn wcstol(host: &dyn Host, errno: usize, a: &[usize; 6]) -> SysResult {
    let text = user::wstr(host, a[0])?;
    let parsed = parse(&text, base_of(a[2])?);
    if a[1] != 0 {
        user::put_u64(host, a[1], (a[0] + parsed.used * 4) as u64)?;
    }
    number(host, errno, &parsed, false)
}

fn number(host: &dyn Host, errno: usize, parsed: &Parsed, unsigned: bool) -> SysResult {
    if unsigned {
        if parsed.overflow {
            user::put_i32(host, errno, ERANGE)?;
            return Ok(-1);
        }
        let value = if parsed.negative {
            parsed.magnitude.wrapping_neg()
        } else {
            parsed.magnitude
        };
        return Ok(value as isize);
    }
    match signed(parsed) {
        Ok(value) => Ok(value as isize),
        Err(limit) => {
            user::put_i32(host, errno, ERANGE)?;
            Ok(limit as isize)
        }
    }
}

/// `strstr(haystack, needle)`.
pub fn strstr(host: &dyn Host, haystack: usize, needle: usize) -> SysResult {
    let hay = user::cstr(host, haystack)?;
    let needle = user::cstr(host, needle)?;
    if needle.is_empty() {
        return Ok(haystack as isize);
    }
    Ok(hay
        .windows(needle.len())
        .position(|window| window == needle)
        .map_or(0, |at| (haystack + at) as isize))
}

/// `strdup(text)`.
pub fn strdup(host: &dyn Host, library: &Library, text: usize) -> SysResult {
    let bytes = user::cstr(host, text)?;
    let copy = crate::heap::malloc(host, library, bytes.len() + 1)? as usize;
    user::put_cstr(host, copy, &bytes)?;
    Ok(copy as isize)
}

/// `__strlcat_chk(dst, src, size, dstlen)`: `strlcat` with the size the
/// compiler knew the destination to have.
pub fn strlcat(host: &dyn Host, dst: usize, src: usize, size: usize) -> SysResult {
    let have = user::cstr(host, dst)?;
    let add = user::cstr(host, src)?;
    if have.len() >= size {
        return Ok((size + add.len()) as isize);
    }
    let room = size - have.len() - 1;
    user::put_cstr(host, dst + have.len(), &add[..add.len().min(room)])?;
    Ok((have.len() + add.len()) as isize)
}

/// `__strcat_chk(dst, src, dstlen)` and `__strncat_chk(dst, src, n, dstlen)`:
/// at most `limit` bytes of `src` after what `dst` already holds.
pub fn strcat(host: &dyn Host, dst: usize, src: usize, limit: usize) -> SysResult {
    let have = user::cstr(host, dst)?;
    let add = user::cstr(host, src)?;
    user::put_cstr(host, dst + have.len(), &add[..add.len().min(limit)])?;
    Ok(dst as isize)
}

/// `wcsncpy(dst, src, n)`: at most `n` wide characters, zero-filled to `n`.
pub fn wcsncpy(host: &dyn Host, dst: usize, src: usize, n: usize) -> SysResult {
    let text = user::wstr(host, src)?;
    let mut out = Vec::with_capacity(n * 4);
    for index in 0..n {
        out.extend_from_slice(&text.get(index).copied().unwrap_or(0).to_le_bytes());
    }
    user::put(host, dst, &out)?;
    Ok(dst as isize)
}

/// A handful of messages, by Darwin's numbering; the rest are numbered.
fn message(errno: i32) -> Option<&'static str> {
    Some(match errno {
        0 => "Undefined error: 0",
        1 => "Operation not permitted",
        2 => "No such file or directory",
        3 => "No such process",
        4 => "Interrupted system call",
        5 => "Input/output error",
        9 => "Bad file descriptor",
        12 => "Cannot allocate memory",
        13 => "Permission denied",
        14 => "Bad address",
        17 => "File exists",
        20 => "Not a directory",
        21 => "Is a directory",
        22 => "Invalid argument",
        24 => "Too many open files",
        25 => "Inappropriate ioctl for device",
        28 => "No space left on device",
        32 => "Broken pipe",
        34 => "Result too large",
        35 => "Resource temporarily unavailable",
        60 => "Operation timed out",
        63 => "File name too long",
        78 => "Function not implemented",
        _ => return None,
    })
}

/// `strerror(errno)`: the message, in a buffer of the library's own that the
/// next call overwrites, which is what C says of it.
pub fn strerror(host: &dyn Host, library: &Library, errno: usize) -> SysResult {
    let at = (library.private() + PRIVATE_STRERROR) as usize;
    let errno = errno as i32;
    match message(errno) {
        Some(text) => user::put_cstr(host, at, text.as_bytes())?,
        None => user::put_cstr(
            host,
            at,
            alloc::format!("Unknown error: {errno}").as_bytes(),
        )?,
    }
    Ok(at as isize)
}

/// `setlocale(category, name)`: asking is answered with "C"; setting succeeds
/// only for the locale there is.
pub fn setlocale(host: &dyn Host, library: &Library, name: usize) -> SysResult {
    let c = (library.private() + PRIVATE_TEXT_C) as isize;
    if name == 0 {
        return Ok(c);
    }
    match user::cstr(host, name)?.as_slice() {
        b"" | b"C" | b"POSIX" => Ok(c),
        _ => Ok(0),
    }
}

/// `nl_langinfo(item)`. `CODESET` is item 0 on Darwin; the other items have
/// no text here and answer with the empty string, as an unknown item does.
pub fn nl_langinfo(library: &Library, item: usize) -> SysResult {
    let at = if item == 0 {
        PRIVATE_TEXT_UTF8
    } else {
        PRIVATE_TEXT_EMPTY
    };
    Ok((library.private() + at) as isize)
}

/// One character from the front of `bytes`: what it is and how long, `None`
/// if the bytes so far are the start of one, or an error if they are not
/// UTF-8.
fn decode(bytes: &[u8]) -> Result<Option<(u32, usize)>, i32> {
    let Some(&lead) = bytes.first() else {
        return Ok(None);
    };
    let (len, mut value) = match lead {
        0x00..=0x7F => return Ok(Some((u32::from(lead), 1))),
        0xC2..=0xDF => (2, u32::from(lead & 0x1F)),
        0xE0..=0xEF => (3, u32::from(lead & 0x0F)),
        0xF0..=0xF4 => (4, u32::from(lead & 0x07)),
        _ => return Err(EILSEQ),
    };
    for index in 1..len {
        match bytes.get(index) {
            Some(byte) if byte & 0xC0 == 0x80 => value = value << 6 | u32::from(byte & 0x3F),
            Some(_) => return Err(EILSEQ),
            None => return Ok(None),
        }
    }
    let shortest = [0, 0, 0x80, 0x800, 0x1_0000][len];
    if value < shortest || char::from_u32(value).is_none() {
        return Err(EILSEQ);
    }
    Ok(Some((value, len)))
}

/// `mbstowcs(dst, src, n)`: the count of wide characters, without the
/// terminator; with a null `dst`, the count the whole string needs.
pub fn mbstowcs(host: &dyn Host, dst: usize, src: usize, n: usize) -> SysResult {
    let bytes = user::cstr(host, src)?;
    let mut wide = Vec::new();
    let mut at = 0;
    while at < bytes.len() {
        let (value, len) = decode(&bytes[at..])?.ok_or(EILSEQ)?;
        wide.push(value);
        at += len;
    }
    if dst == 0 {
        return Ok(wide.len() as isize);
    }
    let count = wide.len().min(n);
    let mut out = Vec::with_capacity((count + 1) * 4);
    for value in &wide[..count] {
        out.extend_from_slice(&value.to_le_bytes());
    }
    if count < n {
        out.extend_from_slice(&0u32.to_le_bytes());
    }
    user::put(host, dst, &out)?;
    Ok(count as isize)
}

/// `wcstombs(dst, src, n)`: the count of bytes, without the terminator. A
/// character that would be cut in half by `n` is not written at all.
pub fn wcstombs(host: &dyn Host, dst: usize, src: usize, n: usize) -> SysResult {
    let wide = user::wstr(host, src)?;
    let mut out = Vec::new();
    for value in wide {
        let mut utf8 = [0u8; 4];
        let text = char::from_u32(value).ok_or(EILSEQ)?.encode_utf8(&mut utf8);
        if dst != 0 && out.len() + text.len() > n {
            break;
        }
        out.extend_from_slice(text.as_bytes());
    }
    if dst == 0 {
        return Ok(out.len() as isize);
    }
    let count = out.len();
    if count < n {
        out.push(0);
    }
    user::put(host, dst, &out)?;
    Ok(count as isize)
}

/// `mbrtowc(pwc, s, n, state)`: one character. UTF-8 needs no shift state, so
/// an incomplete character is reported and nothing of it is kept.
pub fn mbrtowc(host: &dyn Host, pwc: usize, s: usize, n: usize) -> SysResult {
    if s == 0 {
        return Ok(0);
    }
    let bytes = user::bytes(host, s, n.min(4))?;
    match decode(&bytes)? {
        None => Ok(-2),
        Some((value, len)) => {
            if pwc != 0 {
                user::put_u32(host, pwc, value)?;
            }
            Ok(if value == 0 { 0 } else { len as isize })
        }
    }
}

/// Darwin's `_RuneLocale`, filled in for the C locale: what the `isalpha`
/// family reads inline for a byte below 128.
pub fn rune_locale() -> Vec<u8> {
    const ALPHA: u32 = 0x100;
    const CONTROL: u32 = 0x200;
    const DIGIT: u32 = 0x400;
    const GRAPH: u32 = 0x800;
    const LOWER: u32 = 0x1000;
    const PUNCT: u32 = 0x2000;
    const SPACE: u32 = 0x4000;
    const UPPER: u32 = 0x8000;
    const HEX: u32 = 0x1_0000;
    const BLANK: u32 = 0x2_0000;
    const PRINT: u32 = 0x4_0000;
    /// Where the three tables are, past the magic, the encoding name, the two
    /// conversion pointers and the invalid rune.
    const TYPES: usize = 60;
    const LOWERS: usize = TYPES + 256 * 4;
    const UPPERS: usize = LOWERS + 256 * 4;

    let mut out = alloc::vec![0u8; 0xd00];
    out[..8].copy_from_slice(b"RuneMagA");
    out[8..12].copy_from_slice(b"NONE");
    for c in 0..256usize {
        let byte = c as u8;
        let mut kind = 0;
        if c < 128 {
            if byte.is_ascii_control() {
                kind |= CONTROL;
            }
            if byte.is_ascii_digit() {
                kind |= DIGIT | HEX | (u32::from(byte - b'0'));
            }
            if byte.is_ascii_uppercase() {
                kind |= UPPER | ALPHA;
            }
            if byte.is_ascii_lowercase() {
                kind |= LOWER | ALPHA;
            }
            if byte.is_ascii_hexdigit() && !byte.is_ascii_digit() {
                kind |= HEX | (u32::from(byte.to_ascii_lowercase() - b'a') + 10);
            }
            if byte.is_ascii_punctuation() {
                kind |= PUNCT;
            }
            if byte.is_ascii_graphic() {
                kind |= GRAPH | PRINT;
            }
            if matches!(byte, b' ' | 9..=13) {
                kind |= SPACE;
            }
            if matches!(byte, b' ' | b'\t') {
                kind |= BLANK;
            }
            if byte == b' ' {
                kind |= PRINT;
            }
        }
        out[TYPES + c * 4..TYPES + c * 4 + 4].copy_from_slice(&kind.to_le_bytes());
        let lower = u32::from(byte.to_ascii_lowercase());
        let upper = u32::from(byte.to_ascii_uppercase());
        out[LOWERS + c * 4..LOWERS + c * 4 + 4].copy_from_slice(&lower.to_le_bytes());
        out[UPPERS + c * 4..UPPERS + c * 4 + 4].copy_from_slice(&upper.to_le_bytes());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::MockHost;

    fn wide(text: &str) -> Vec<u32> {
        text.chars().map(u32::from).collect()
    }

    #[test]
    fn a_number_is_read_with_its_sign_and_base() {
        let read = |text: &str, base: u32| {
            let parsed = parse(&wide(text), base);
            (signed(&parsed), parsed.used)
        };
        assert_eq!(read("  -42xyz", 10), (Ok(-42), 5));
        assert_eq!(read("0x1F", 0), (Ok(31), 4));
        assert_eq!(read("0x1F", 16), (Ok(31), 4));
        assert_eq!(read("017", 0), (Ok(15), 3));
        assert_eq!(read("z", 36), (Ok(35), 1));
        // No digits leaves the end at the start; "0x" alone is just a zero.
        assert_eq!(read("abc", 10), (Ok(0), 0));
        assert_eq!(read("0xg", 16), (Ok(0), 1));
        assert_eq!(read("9223372036854775807", 10), (Ok(i64::MAX), 19));
        assert_eq!(read("9223372036854775808", 10), (Err(i64::MAX), 19));
        assert_eq!(read("-9223372036854775808", 10), (Ok(i64::MIN), 20));
        assert_eq!(read("-99999999999999999999", 10), (Err(i64::MIN), 21));
    }

    #[test]
    fn utf8_is_decoded_strictly() {
        assert_eq!(decode(b"a"), Ok(Some((0x61, 1))));
        assert_eq!(decode("中".as_bytes()), Ok(Some((0x4E2D, 3))));
        assert_eq!(decode(&"中".as_bytes()[..2]), Ok(None), "the start of one");
        assert_eq!(decode(&[0xC0, 0x80]), Err(EILSEQ), "an overlong form");
        assert_eq!(decode(&[0xED, 0xA0, 0x80]), Err(EILSEQ), "a surrogate");
        assert_eq!(decode(&[0x80]), Err(EILSEQ), "a continuation first");
    }

    #[test]
    fn the_two_string_forms_convert_both_ways() {
        let host = MockHost::default();
        host.mem.borrow_mut().resize(0x1000, 0);
        let text = "a中\u{1F600}";
        host.mem.borrow_mut()[0x100..0x100 + text.len()].copy_from_slice(text.as_bytes());
        assert_eq!(mbstowcs(&host, 0, 0x100, 0), Ok(3), "asking for the length");
        assert_eq!(mbstowcs(&host, 0x200, 0x100, 16), Ok(3));
        assert_eq!(user::wstr(&host, 0x200).unwrap(), wide(text));
        assert_eq!(wcstombs(&host, 0x300, 0x200, 64), Ok(text.len() as isize));
        assert_eq!(user::cstr(&host, 0x300).unwrap(), text.as_bytes());
        // Five bytes hold the first two characters and not half of the third.
        assert_eq!(wcstombs(&host, 0x400, 0x200, 5), Ok(4));
    }

    #[test]
    fn the_rune_table_classifies_ascii() {
        let table = rune_locale();
        let kind = |c: u8| {
            let at = 60 + c as usize * 4;
            u32::from_le_bytes(table[at..at + 4].try_into().unwrap())
        };
        assert_ne!(kind(b'a') & 0x1000, 0, "lower");
        assert_ne!(kind(b'A') & 0x8000, 0, "upper");
        assert_eq!(kind(b'f') & 0xff, 15, "a hex digit carries its value");
        assert_ne!(kind(b' ') & 0x4000, 0, "space");
        assert_eq!(kind(b' ') & 0x800, 0, "but not graphic");
        assert_eq!(kind(200), 0, "nothing above ASCII in the C locale");
        let lower = 60 + 256 * 4 + b'Q' as usize * 4;
        assert_eq!(table[lower], b'q');
    }
}
