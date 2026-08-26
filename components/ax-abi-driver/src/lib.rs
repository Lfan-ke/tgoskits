//! Driver ABI compatibility for foreign personalities.
//!
//! Windows drivers are reached with `NtDeviceIoControlFile`, whose control code
//! is a packed `CTL_CODE(DeviceType, Function, Method, Access)` that also tells
//! the caller how buffers are passed. A personality that wants to satisfy such a
//! request on top of `ax-driver` must first decode that code, then route the
//! call to a backing device. This crate is that thin, dependency-free boundary:
//! [`Ioctl`] decodes the code (transcribed from `winioctl.h` `CTL_CODE`), and
//! [`DeviceControl`] is the capability the kernel implements over `ax-driver`.

#![no_std]

/// How an NT device control passes its buffers (`METHOD_*` in `winioctl.h`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    /// `METHOD_BUFFERED`: system copies in and out through a single buffer.
    Buffered,
    /// `METHOD_IN_DIRECT`: input buffered, output described by an MDL.
    InDirect,
    /// `METHOD_OUT_DIRECT`: output buffered-in, described by an MDL.
    OutDirect,
    /// `METHOD_NEITHER`: driver accesses user buffers directly.
    Neither,
}

impl Method {
    const fn from_bits(bits: u32) -> Method {
        match bits & 0b11 {
            0 => Method::Buffered,
            1 => Method::InDirect,
            2 => Method::OutDirect,
            _ => Method::Neither,
        }
    }
}

/// A decoded NT device I/O control code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IoctlParts {
    /// Target device class (`FILE_DEVICE_*`).
    pub device_type: u16,
    /// Driver-defined function number (12 bits).
    pub function: u16,
    /// Buffer-passing method.
    pub method: Method,
    /// Required access (`FILE_ANY_ACCESS`/`READ`/`WRITE`, 2 bits).
    pub access: u8,
}

/// An NT device I/O control code, packed as `CTL_CODE` does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(transparent)]
pub struct Ioctl(pub u32);

impl Ioctl {
    /// Pack a control code, the `CTL_CODE(DeviceType, Function, Method, Access)`
    /// macro: `(device_type << 16) | (access << 14) | (function << 2) | method`.
    pub const fn new(device_type: u16, function: u16, method: Method, access: u8) -> Ioctl {
        Ioctl(
            (device_type as u32) << 16
                | (access as u32) << 14
                | (function as u32) << 2
                | method as u32,
        )
    }

    /// Decode the packed fields.
    pub const fn decode(self) -> IoctlParts {
        IoctlParts {
            device_type: (self.0 >> 16) as u16,
            function: ((self.0 >> 2) & 0xFFF) as u16,
            method: Method::from_bits(self.0),
            access: ((self.0 >> 14) & 0b11) as u8,
        }
    }
}

/// The capability a personality needs to service device I/O: route a decoded
/// NT control to the `ax-driver` device named by `device` (an NT device path
/// such as `\Device\Null`). Implemented by the kernel; this crate stays free of
/// driver-runtime types so it can be reused and unit-tested in isolation.
pub trait DeviceControl {
    /// Perform the control, returning the number of bytes written to `output`.
    ///
    /// # Errors
    ///
    /// Returns a negative errno when the device is unknown or the control fails,
    /// which the personality maps to the NTSTATUS its caller expects.
    fn device_control(
        &mut self,
        device: &str,
        code: Ioctl,
        input: &[u8],
        output: &mut [u8],
    ) -> Result<usize, i32>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn packs_and_decodes_round_trip() {
        let code = Ioctl::new(0x0015, 0x0abc, Method::Neither, 0b11);
        let parts = code.decode();
        assert_eq!(parts.device_type, 0x0015);
        assert_eq!(parts.function, 0x0abc);
        assert_eq!(parts.method, Method::Neither);
        assert_eq!(parts.access, 0b11);
    }

    #[test]
    fn decodes_a_real_ioctl_constant() {
        // IOCTL_DISK_GET_DRIVE_GEOMETRY = CTL_CODE(FILE_DEVICE_DISK=7, 0,
        // METHOD_BUFFERED, FILE_ANY_ACCESS) = 0x0007_0000.
        let parts = Ioctl(0x0007_0000).decode();
        assert_eq!(parts.device_type, 7);
        assert_eq!(parts.function, 0);
        assert_eq!(parts.method, Method::Buffered);
        assert_eq!(parts.access, 0);
    }

    #[test]
    fn method_bits_map_to_all_variants() {
        assert_eq!(Ioctl(0).decode().method, Method::Buffered);
        assert_eq!(Ioctl(1).decode().method, Method::InDirect);
        assert_eq!(Ioctl(2).decode().method, Method::OutDirect);
        assert_eq!(Ioctl(3).decode().method, Method::Neither);
    }

    // A trivial DeviceControl that echoes input, proving the boundary is usable.
    struct NullDevice;
    impl DeviceControl for NullDevice {
        fn device_control(
            &mut self,
            device: &str,
            _code: Ioctl,
            input: &[u8],
            output: &mut [u8],
        ) -> Result<usize, i32> {
            if device != r"\Device\Null" {
                return Err(-2); // -ENOENT
            }
            let n = input.len().min(output.len());
            output[..n].copy_from_slice(&input[..n]);
            Ok(n)
        }
    }

    #[test]
    fn device_control_boundary_routes_and_reports_errors() {
        let mut dev = NullDevice;
        let mut out = [0u8; 4];
        let n = dev
            .device_control(r"\Device\Null", Ioctl(0x0007_0000), b"hi", &mut out)
            .unwrap();
        assert_eq!(&out[..n], b"hi");
        assert_eq!(
            dev.device_control(r"\Device\Missing", Ioctl(0), b"", &mut out),
            Err(-2)
        );
    }
}
