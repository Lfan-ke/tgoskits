//! The `printf` family.
//!
//! A variadic call keeps its arguments where the C ABI puts them: the integer
//! ones in what is left of the six argument registers and then on the stack
//! above the return address, the floating-point ones in `xmm0` to `xmm7`. A
//! trap carries the registers and the stack pointer, so the integer and
//! pointer arguments are all reachable from here; the vector registers are not
//! part of what a trap hands over, so a floating-point argument passed
//! directly is reported rather than guessed at. A `va_list` is different: its
//! owner already spilled both kinds to memory, and both are read from there.

use alloc::{format, string::String, vec::Vec};

use ax_abi_port::{Host, SysResult};

use crate::{libc::Frame, system::Library, user};

/// `EINVAL`.
const EINVAL: i32 = 22;

/// Where a conversion's next argument comes from.
pub trait Args {
    fn int(&mut self) -> Result<u64, i32>;
    /// `None` when the call cannot carry a floating-point argument this far.
    fn float(&mut self) -> Result<Option<f64>, i32>;
}

/// The arguments of a call as it trapped.
pub struct Variadic<'a> {
    host: &'a dyn Host,
    registers: &'a [usize; 6],
    next: usize,
    stack: usize,
}

impl<'a> Variadic<'a> {
    /// `fixed` is how many named arguments come before the variable ones.
    pub fn new(host: &'a dyn Host, frame: &'a Frame, fixed: usize) -> Self {
        Variadic {
            host,
            registers: &frame.a,
            next: fixed,
            // The stub is entered by a call and pushes nothing, so the first
            // stack argument is one word above the return address.
            stack: frame.sp + 8,
        }
    }
}

impl Args for Variadic<'_> {
    fn int(&mut self) -> Result<u64, i32> {
        if self.next < 6 {
            self.next += 1;
            return Ok(self.registers[self.next - 1] as u64);
        }
        let value = user::u64_at(self.host, self.stack)?;
        self.stack += 8;
        Ok(value)
    }

    fn float(&mut self) -> Result<Option<f64>, i32> {
        Ok(None)
    }
}

/// A `va_list` in the caller's memory: System V's `gp_offset`, `fp_offset`,
/// `overflow_arg_area` and `reg_save_area`.
pub struct VaList<'a> {
    host: &'a dyn Host,
    at: usize,
}

impl<'a> VaList<'a> {
    pub fn new(host: &'a dyn Host, at: usize) -> Self {
        VaList { host, at }
    }

    fn overflow(&mut self) -> Result<u64, i32> {
        let area = user::u64_at(self.host, self.at + 8)? as usize;
        let value = user::u64_at(self.host, area)?;
        user::put_u64(self.host, self.at + 8, area as u64 + 8)?;
        Ok(value)
    }
}

impl Args for VaList<'_> {
    fn int(&mut self) -> Result<u64, i32> {
        let offset = user::u32_at(self.host, self.at)?;
        if offset >= 48 {
            return self.overflow();
        }
        let save = user::u64_at(self.host, self.at + 16)? as usize;
        user::put_u32(self.host, self.at, offset + 8)?;
        user::u64_at(self.host, save + offset as usize)
    }

    fn float(&mut self) -> Result<Option<f64>, i32> {
        let offset = user::u32_at(self.host, self.at + 4)?;
        let bits = if offset >= 176 {
            self.overflow()?
        } else {
            let save = user::u64_at(self.host, self.at + 16)? as usize;
            user::put_u32(self.host, self.at + 4, offset + 16)?;
            user::u64_at(self.host, save + offset as usize)?
        };
        Ok(Some(f64::from_bits(bits)))
    }
}

/// One `%` conversion, as written.
#[derive(Default)]
struct Spec {
    left: bool,
    plus: bool,
    space: bool,
    alt: bool,
    zero: bool,
    width: usize,
    precision: Option<usize>,
    /// How many bytes the integer argument is: 1, 2, 4 or 8.
    size: u8,
    wide: bool,
}

/// What `fmt` and its arguments spell out.
pub fn format(host: &dyn Host, fmt: &[u8], args: &mut dyn Args) -> Result<Vec<u8>, i32> {
    let mut out = Vec::new();
    let mut at = 0;
    while at < fmt.len() {
        let byte = fmt[at];
        at += 1;
        if byte != b'%' {
            out.push(byte);
            continue;
        }
        let mut spec = Spec {
            size: 4,
            ..Spec::default()
        };
        while let Some(flag) = fmt.get(at) {
            match flag {
                b'-' => spec.left = true,
                b'+' => spec.plus = true,
                b' ' => spec.space = true,
                b'#' => spec.alt = true,
                b'0' => spec.zero = true,
                _ => break,
            }
            at += 1;
        }
        if fmt.get(at) == Some(&b'*') {
            at += 1;
            let width = args.int()? as i32;
            spec.left |= width < 0;
            spec.width = width.unsigned_abs() as usize;
        } else {
            spec.width = number(fmt, &mut at);
        }
        if fmt.get(at) == Some(&b'.') {
            at += 1;
            if fmt.get(at) == Some(&b'*') {
                at += 1;
                let precision = args.int()? as i32;
                spec.precision = (precision >= 0).then_some(precision as usize);
            } else {
                spec.precision = Some(number(fmt, &mut at));
            }
        }
        loop {
            match fmt.get(at) {
                Some(b'h') if fmt.get(at + 1) == Some(&b'h') => {
                    spec.size = 1;
                    at += 2;
                }
                Some(b'h') => {
                    spec.size = 2;
                    at += 1;
                }
                Some(b'l') => {
                    spec.size = 8;
                    spec.wide = true;
                    at += 1;
                }
                Some(b'q' | b'j' | b'z' | b't' | b'L') => {
                    spec.size = 8;
                    at += 1;
                }
                _ => break,
            }
        }
        let Some(conversion) = fmt.get(at).copied() else {
            return Err(EINVAL);
        };
        at += 1;
        match conversion {
            b'%' => out.push(b'%'),
            b'd' | b'i' => {
                let raw = args.int()?;
                let value = match spec.size {
                    1 => raw as i8 as i64,
                    2 => raw as i16 as i64,
                    4 => raw as i32 as i64,
                    _ => raw as i64,
                };
                let sign = if value < 0 {
                    "-"
                } else if spec.plus {
                    "+"
                } else if spec.space {
                    " "
                } else {
                    ""
                };
                integer(&mut out, &spec, sign, &format!("{}", value.unsigned_abs()));
            }
            b'u' | b'x' | b'X' | b'o' => {
                let raw = args.int()?;
                let value = match spec.size {
                    1 => raw as u8 as u64,
                    2 => raw as u16 as u64,
                    4 => raw as u32 as u64,
                    _ => raw,
                };
                let (digits, prefix) = match conversion {
                    b'u' => (format!("{value}"), ""),
                    b'x' => (format!("{value:x}"), "0x"),
                    b'X' => (format!("{value:X}"), "0X"),
                    _ => (format!("{value:o}"), "0"),
                };
                let prefix = if spec.alt && value != 0 { prefix } else { "" };
                integer(&mut out, &spec, prefix, &digits);
            }
            b'p' => {
                let value = args.int()?;
                pad(&mut out, &spec, format!("0x{value:x}").as_bytes());
            }
            b'c' => {
                let value = args.int()? as u32;
                if spec.wide {
                    let mut utf8 = [0u8; 4];
                    let text = char::from_u32(value).unwrap_or('?').encode_utf8(&mut utf8);
                    pad(&mut out, &spec, text.as_bytes());
                } else {
                    pad(&mut out, &spec, &[value as u8]);
                }
            }
            b's' => {
                let at = args.int()? as usize;
                let mut text = if at == 0 {
                    b"(null)".to_vec()
                } else if spec.wide {
                    let wide = user::wstr(host, at)?;
                    let text: String = wide
                        .iter()
                        .map(|c| char::from_u32(*c).unwrap_or('?'))
                        .collect();
                    text.into_bytes()
                } else {
                    user::cstr(host, at)?
                };
                if let Some(limit) = spec.precision {
                    text.truncate(limit);
                }
                pad(&mut out, &spec, &text);
            }
            b'f' | b'F' | b'e' | b'E' | b'g' | b'G' => match args.float()? {
                Some(value) => {
                    let text = float(&spec, conversion, value);
                    let numeric = Spec {
                        zero: spec.zero && value.is_finite(),
                        ..Spec {
                            left: spec.left,
                            width: spec.width,
                            size: 8,
                            ..Spec::default()
                        }
                    };
                    let (sign, digits) = match text.strip_prefix(['-', '+', ' ']) {
                        Some(rest) => (&text[..1], rest),
                        None => ("", text.as_str()),
                    };
                    integer(&mut out, &numeric, sign, digits);
                }
                None => {
                    host.platform().trace(
                        "a floating-point argument passed directly to a printf call is not \
                         carried by the trap",
                    );
                    pad(&mut out, &spec, b"?");
                }
            },
            _ => return Err(EINVAL),
        }
    }
    Ok(out)
}

/// The decimal number at `at`, which may be absent.
fn number(fmt: &[u8], at: &mut usize) -> usize {
    let mut value = 0usize;
    while let Some(digit) = fmt.get(*at).filter(|b| b.is_ascii_digit()) {
        value = value
            .saturating_mul(10)
            .saturating_add((digit - b'0') as usize);
        *at += 1;
    }
    value
}

/// `text` in a field of the width the conversion asks for.
fn pad(out: &mut Vec<u8>, spec: &Spec, text: &[u8]) {
    let fill = spec.width.saturating_sub(text.len());
    if spec.left {
        out.extend_from_slice(text);
        out.resize(out.len() + fill, b' ');
    } else {
        out.resize(out.len() + fill, b' ');
        out.extend_from_slice(text);
    }
}

/// A number: its sign or base prefix, zeros up to the precision, its digits,
/// and whatever the width still asks for.
fn integer(out: &mut Vec<u8>, spec: &Spec, prefix: &str, digits: &str) {
    let zeros = spec
        .precision
        .map_or(0, |precision| precision.saturating_sub(digits.len()));
    let len = prefix.len() + zeros + digits.len();
    let fill = spec.width.saturating_sub(len);
    // A precision turns the zero flag off, as C says it does.
    let zero_fill = spec.zero && !spec.left && spec.precision.is_none();
    if !spec.left && !zero_fill {
        out.resize(out.len() + fill, b' ');
    }
    out.extend_from_slice(prefix.as_bytes());
    if zero_fill {
        out.resize(out.len() + fill, b'0');
    }
    out.resize(out.len() + zeros, b'0');
    out.extend_from_slice(digits.as_bytes());
    if spec.left {
        out.resize(out.len() + fill, b' ');
    }
}

/// A floating-point conversion, sign included, before any padding.
fn float(spec: &Spec, conversion: u8, value: f64) -> String {
    let upper = conversion.is_ascii_uppercase();
    let sign = if value.is_sign_negative() && !value.is_nan() {
        "-"
    } else if spec.plus {
        "+"
    } else if spec.space {
        " "
    } else {
        ""
    };
    let magnitude = value.abs();
    let body = if value.is_nan() {
        String::from("nan")
    } else if value.is_infinite() {
        String::from("inf")
    } else {
        let precision = spec.precision.unwrap_or(6);
        match conversion.to_ascii_lowercase() {
            b'f' => fixed(magnitude, precision, spec.alt),
            b'e' => exponent(magnitude, precision, spec.alt),
            _ => {
                let precision = precision.max(1);
                let power = power_of(magnitude, precision - 1);
                let text = if power >= -4 && power < precision as i32 {
                    fixed(magnitude, (precision as i32 - 1 - power) as usize, spec.alt)
                } else {
                    exponent(magnitude, precision - 1, spec.alt)
                };
                if spec.alt { text } else { trim(&text) }
            }
        }
    };
    let body = if upper {
        body.to_ascii_uppercase()
    } else {
        body
    };
    format!("{sign}{body}")
}

fn fixed(value: f64, precision: usize, point: bool) -> String {
    let text = format!("{value:.precision$}");
    if point && precision == 0 {
        text + "."
    } else {
        text
    }
}

/// `d.ddde+xx`, with the two-digit exponent C writes.
fn exponent(value: f64, precision: usize, point: bool) -> String {
    let text = format!("{value:.precision$e}");
    let (mantissa, power) = text.split_once('e').unwrap_or((&text, "0"));
    let power: i32 = power.parse().unwrap_or(0);
    let mantissa = if point && precision == 0 {
        format!("{mantissa}.")
    } else {
        String::from(mantissa)
    };
    let sign = if power < 0 { '-' } else { '+' };
    format!("{mantissa}e{sign}{:02}", power.unsigned_abs())
}

/// The decimal exponent `value` has once rounded to `precision` digits after
/// the first, which is what `%g` chooses its style by.
fn power_of(value: f64, precision: usize) -> i32 {
    let text = format!("{value:.precision$e}");
    text.split_once('e')
        .and_then(|(_, power)| power.parse().ok())
        .unwrap_or(0)
}

/// `%g` drops the zeros a fixed precision leaves behind, and the point with
/// them if nothing follows it.
fn trim(text: &str) -> String {
    let (number, tail) = match text.find('e') {
        Some(at) => text.split_at(at),
        None => (text, ""),
    };
    let number = if number.contains('.') {
        number.trim_end_matches('0').trim_end_matches('.')
    } else {
        number
    };
    format!("{number}{tail}")
}

/// Put `text` in a buffer of `size` bytes the way `snprintf` does: as much as
/// fits with a terminator after it, answered with the length it wanted.
fn store(host: &dyn Host, buf: usize, size: usize, text: &[u8]) -> SysResult {
    if size != 0 {
        let fits = text.len().min(size - 1);
        user::put_cstr(host, buf, &text[..fits])?;
    }
    Ok(text.len() as isize)
}

/// `snprintf(buf, size, fmt, ...)`.
pub fn snprintf(host: &dyn Host, frame: &Frame) -> SysResult {
    let fmt = user::cstr(host, frame.a[2])?;
    let text = format(host, &fmt, &mut Variadic::new(host, frame, 3))?;
    store(host, frame.a[0], frame.a[1], &text)
}

/// `sprintf(buf, fmt, ...)`.
pub fn sprintf(host: &dyn Host, frame: &Frame) -> SysResult {
    let fmt = user::cstr(host, frame.a[1])?;
    let text = format(host, &fmt, &mut Variadic::new(host, frame, 2))?;
    store(host, frame.a[0], usize::MAX, &text)
}

/// `__sprintf_chk(buf, flag, buflen, fmt, ...)`: `sprintf` with the size the
/// compiler knew the buffer to have.
pub fn sprintf_chk(host: &dyn Host, frame: &Frame) -> SysResult {
    let fmt = user::cstr(host, frame.a[3])?;
    let text = format(host, &fmt, &mut Variadic::new(host, frame, 4))?;
    store(host, frame.a[0], frame.a[2], &text)
}

/// `vsnprintf(buf, size, fmt, ap)`.
pub fn vsnprintf(host: &dyn Host, frame: &Frame) -> SysResult {
    let fmt = user::cstr(host, frame.a[2])?;
    let text = format(host, &fmt, &mut VaList::new(host, frame.a[3]))?;
    store(host, frame.a[0], frame.a[1], &text)
}

/// `fprintf(file, fmt, ...)`.
pub fn fprintf(host: &dyn Host, library: &Library, frame: &Frame) -> SysResult {
    let fmt = user::cstr(host, frame.a[1])?;
    let text = format(host, &fmt, &mut Variadic::new(host, frame, 2))?;
    crate::stdio::emit(host, library, frame.a[0], &text)
}

/// `vfprintf(file, fmt, ap)`.
pub fn vfprintf(host: &dyn Host, library: &Library, frame: &Frame) -> SysResult {
    let fmt = user::cstr(host, frame.a[1])?;
    let text = format(host, &fmt, &mut VaList::new(host, frame.a[2]))?;
    crate::stdio::emit(host, library, frame.a[0], &text)
}

/// `printf(fmt, ...)`.
pub fn printf(host: &dyn Host, library: &Library, frame: &Frame) -> SysResult {
    let fmt = user::cstr(host, frame.a[0])?;
    let text = format(host, &fmt, &mut Variadic::new(host, frame, 1))?;
    let out = crate::stdio::standard(library, 1) as usize;
    crate::stdio::emit(host, library, out, &text)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::MockHost;

    struct Given(Vec<u64>, Vec<f64>);

    impl Args for Given {
        fn int(&mut self) -> Result<u64, i32> {
            Ok(self.0.remove(0))
        }

        fn float(&mut self) -> Result<Option<f64>, i32> {
            Ok(Some(self.1.remove(0)))
        }
    }

    fn text(fmt: &str, ints: &[u64], floats: &[f64]) -> String {
        let host = MockHost::default();
        host.mem.borrow_mut().resize(0x1000, 0);
        host.mem.borrow_mut()[0x100..0x106].copy_from_slice(b"hello\0");
        let out = format(
            &host,
            fmt.as_bytes(),
            &mut Given(ints.to_vec(), floats.to_vec()),
        );
        String::from_utf8(out.unwrap()).unwrap()
    }

    #[test]
    fn integers_follow_their_length_and_flags() {
        assert_eq!(
            text("%d|%5d|%-5d|%05d", &[7, 7, 7, 7], &[]),
            "7|    7|7    |00007"
        );
        assert_eq!(text("%d", &[(-3i32) as u32 as u64], &[]), "-3");
        assert_eq!(text("%ld", &[(-3i64) as u64], &[]), "-3");
        assert_eq!(
            text("%zu %lu", &[5, u64::MAX], &[]),
            "5 18446744073709551615"
        );
        assert_eq!(
            text("%x %X %#x %o", &[255, 255, 255, 8], &[]),
            "ff FF 0xff 10"
        );
        assert_eq!(text("%.3d|%+d|% d", &[5, 5, 5], &[]), "005|+5| 5");
        assert_eq!(text("%hhd", &[0x1ff], &[]), "-1");
    }

    #[test]
    fn strings_stop_at_their_precision_and_pad_to_their_width() {
        assert_eq!(
            text("%s|%.2s|%7s|%-7s|", &[0x100; 4], &[]),
            "hello|he|  hello|hello  |"
        );
        assert_eq!(text("%s", &[0], &[]), "(null)");
        assert_eq!(text("%c%%%c", &[b'a' as u64, b'b' as u64], &[]), "a%b");
        assert_eq!(text("%*d|%.*s", &[4, 9, 3, 0x100], &[]), "   9|hel");
    }

    #[test]
    fn floats_come_out_the_way_c_writes_them() {
        assert_eq!(text("%f", &[], &[1.5]), "1.500000");
        assert_eq!(text("%.2f", &[], &[-2.345]), "-2.35");
        assert_eq!(text("%e", &[], &[150.0]), "1.500000e+02");
        assert_eq!(
            text("%g|%g|%g", &[], &[0.0001, 1e-5, 100000.0]),
            "0.0001|1e-05|100000"
        );
        assert_eq!(text("%g", &[], &[1e6]), "1e+06");
        assert_eq!(text("%.17g", &[], &[0.1]), "0.10000000000000001");
        assert_eq!(
            text("%8.3f|%-8.1f|%08.2f", &[], &[3.14159, 2.5, -1.5]),
            "   3.142|2.5     |-0001.50"
        );
        assert_eq!(text("%f %F", &[], &[f64::INFINITY, f64::NAN]), "inf NAN");
    }

    #[test]
    fn a_pointer_is_written_in_hex() {
        assert_eq!(text("%p", &[0x1234], &[]), "0x1234");
    }

    #[test]
    fn a_va_list_hands_out_registers_then_the_overflow_area() {
        let host = MockHost::default();
        host.mem.borrow_mut().resize(0x1000, 0);
        // gp_offset 40: one register slot left, then the overflow area.
        let list = 0x200usize;
        {
            let mut mem = host.mem.borrow_mut();
            mem[list..list + 4].copy_from_slice(&40u32.to_le_bytes());
            mem[list + 4..list + 8].copy_from_slice(&48u32.to_le_bytes());
            mem[list + 8..list + 16].copy_from_slice(&0x400u64.to_le_bytes());
            mem[list + 16..list + 24].copy_from_slice(&0x300u64.to_le_bytes());
            mem[0x300 + 40..0x300 + 48].copy_from_slice(&11u64.to_le_bytes());
            mem[0x300 + 48..0x300 + 56].copy_from_slice(&2.5f64.to_bits().to_le_bytes());
            mem[0x400..0x408].copy_from_slice(&22u64.to_le_bytes());
        }
        let mut args = VaList::new(&host, list);
        assert_eq!(args.int().unwrap(), 11);
        assert_eq!(args.int().unwrap(), 22);
        assert_eq!(args.float().unwrap(), Some(2.5));
    }
}
