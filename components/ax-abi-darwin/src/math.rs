//! The floating-point entries.
//!
//! A `double` travels in a vector register, and a trap carries only the
//! integer ones, so each of these has a stub of its own shape: it moves its
//! arguments' bits into the integer registers, traps, and moves the answer's
//! bits back. On this side the bits are a number again and the arithmetic is
//! `libm`'s.

use ax_abi_port::{Host, SysResult};

use crate::user;

/// Where an entry's arguments are and how its answer goes back.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Shape {
    /// `double f(double)`.
    Unary,
    /// `double f(double, double)`.
    Binary,
    /// `double f(double, double, double)`.
    Ternary,
    /// `double f(double, int)` or `double f(double, T *)`.
    WithInteger,
    /// One `double` in, two out, which is how `__sincos_stret` answers.
    Pair,
}

fn unary(name: &str) -> Option<fn(f64) -> f64> {
    Some(match name {
        "_acos" => libm::acos,
        "_acosh" => libm::acosh,
        "_asin" => libm::asin,
        "_asinh" => libm::asinh,
        "_atan" => libm::atan,
        "_atanh" => libm::atanh,
        "_cbrt" => libm::cbrt,
        "_cos" => libm::cos,
        "_cosh" => libm::cosh,
        "_erf" => libm::erf,
        "_erfc" => libm::erfc,
        "_exp" => libm::exp,
        "_exp2" => libm::exp2,
        "_expm1" => libm::expm1,
        "_log" => libm::log,
        "_log10" => libm::log10,
        "_log1p" => libm::log1p,
        "_log2" => libm::log2,
        "_sin" => libm::sin,
        "_sinh" => libm::sinh,
        "_tan" => libm::tan,
        "_tanh" => libm::tanh,
        _ => return None,
    })
}

fn binary(name: &str) -> Option<fn(f64, f64) -> f64> {
    Some(match name {
        "_atan2" => libm::atan2,
        "_copysign" => libm::copysign,
        "_fmod" => libm::fmod,
        "_hypot" => libm::hypot,
        "_nextafter" => libm::nextafter,
        "_pow" => libm::pow,
        _ => return None,
    })
}

/// The shape of `name`'s stub, or `None` if it is not one of these.
pub fn shape(name: &str) -> Option<Shape> {
    if unary(name).is_some() {
        return Some(Shape::Unary);
    }
    if binary(name).is_some() {
        return Some(Shape::Binary);
    }
    match name {
        "_fma" => Some(Shape::Ternary),
        "_frexp" | "_ldexp" | "_modf" => Some(Shape::WithInteger),
        "___sincos_stret" => Some(Shape::Pair),
        _ => None,
    }
}

/// Serve a floating-point entry. Every argument arrives as the bits its stub
/// moved over, and the answer leaves the same way.
pub fn route(host: &dyn Host, name: &str, a: &[usize; 6]) -> Option<SysResult> {
    let x = f64::from_bits(a[0] as u64);
    let y = f64::from_bits(a[1] as u64);
    let bits = |value: f64| Ok(value.to_bits() as isize);
    if let Some(f) = unary(name) {
        return Some(bits(f(x)));
    }
    if let Some(f) = binary(name) {
        return Some(bits(f(x, y)));
    }
    Some(match name {
        "_fma" => bits(libm::fma(x, y, f64::from_bits(a[2] as u64))),
        "_ldexp" => bits(libm::ldexp(x, a[1] as i32)),
        "_frexp" => {
            let (fraction, exponent) = libm::frexp(x);
            user::put_i32(host, a[1], exponent).map(|()| fraction.to_bits() as isize)
        }
        "_modf" => {
            let (fraction, whole) = libm::modf(x);
            user::put_u64(host, a[1], whole.to_bits()).map(|()| fraction.to_bits() as isize)
        }
        "___sincos_stret" => {
            let (sin, cos) = libm::sincos(x);
            user::put_u64(host, a[1], sin.to_bits())
                .and_then(|()| user::put_u64(host, a[1] + 8, cos.to_bits()))
                .map(|()| 0)
        }
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::MockHost;

    fn call(host: &MockHost, name: &str, a: [usize; 6]) -> f64 {
        f64::from_bits(route(host, name, &a).unwrap().unwrap() as u64)
    }

    #[test]
    fn a_number_goes_in_and_comes_back_as_its_bits() {
        let host = MockHost::default();
        host.mem.borrow_mut().resize(0x1000, 0);
        let b = |value: f64| value.to_bits() as usize;
        assert_eq!(call(&host, "_pow", [b(2.0), b(10.0), 0, 0, 0, 0]), 1024.0);
        assert_eq!(call(&host, "_fmod", [b(7.5), b(2.0), 0, 0, 0, 0]), 1.5);
        assert_eq!(call(&host, "_ldexp", [b(0.75), 4, 0, 0, 0, 0]), 12.0);
        assert_eq!(call(&host, "_log2", [b(8.0), 0, 0, 0, 0, 0]), 3.0);
        assert_eq!(call(&host, "_fma", [b(2.0), b(3.0), b(1.0), 0, 0, 0]), 7.0);
        assert!(call(&host, "_log", [b(-1.0), 0, 0, 0, 0, 0]).is_nan());
    }

    #[test]
    fn the_second_answer_is_stored_where_the_caller_points() {
        let host = MockHost::default();
        host.mem.borrow_mut().resize(0x1000, 0);
        let b = |value: f64| value.to_bits() as usize;
        assert_eq!(call(&host, "_frexp", [b(12.0), 0x100, 0, 0, 0, 0]), 0.75);
        assert_eq!(user::i32_at(&host, 0x100), Ok(4));
        assert_eq!(call(&host, "_modf", [b(-3.25), 0x200, 0, 0, 0, 0]), -0.25);
        assert_eq!(f64::from_bits(user::u64_at(&host, 0x200).unwrap()), -3.0);
        route(&host, "___sincos_stret", &[b(0.0), 0x300, 0, 0, 0, 0]);
        assert_eq!(f64::from_bits(user::u64_at(&host, 0x300).unwrap()), 0.0);
        assert_eq!(f64::from_bits(user::u64_at(&host, 0x308).unwrap()), 1.0);
    }

    #[test]
    fn a_name_that_is_not_arithmetic_is_left_alone() {
        let host = MockHost::default();
        assert!(route(&host, "_write", &[0; 6]).is_none());
        assert_eq!(shape("_write"), None);
        assert_eq!(shape("_sin"), Some(Shape::Unary));
        assert_eq!(shape("_frexp"), Some(Shape::WithInteger));
    }
}
