//! Tells userspace that the display configuration changed.
//!
//! virtio-gpu raises a configuration interrupt when the host resizes the
//! display. Re-reading the new size travels the device's control queue and the
//! uevent allocates, so the interrupt only wakes this worker, which does both
//! in task context. Linux splits the work the same way, in
//! `virtio_gpu_config_changed_work_func()`.

use alloc::{format, string::String, vec::Vec};
use core::sync::atomic::{AtomicU64, Ordering};

use ax_lazyinit::OnceLock;
use linux_raw_sys::netlink::NETLINK_KOBJECT_UEVENT;

use crate::{file::netlink, task::future::IrqNotify};

/// Group 1 is the one udev listens on for kernel uevents.
const UEVENT_GROUP: u32 = 1;
const DEVPATH: &str = "/devices/virtual/drm/card0";

static DISPLAY_CHANGED: IrqNotify = IrqNotify::new();
static SEQNUM: AtomicU64 = AtomicU64::new(1);
static STARTED: OnceLock<()> = OnceLock::new();

/// Runs in the display interrupt: only records that a refresh is due.
pub(crate) fn notify_display_changed() {
    DISPLAY_CHANGED.notify_irq();
}

pub(crate) fn start_worker() {
    STARTED.call_once(|| {
        crate::task::kernel_thread_builder("drm-hotplug".into())
            .spawn(|| {
                loop {
                    DISPLAY_CHANGED.wait();
                    let info = ax_display::framebuffer_refresh_info();
                    let seqnum = SEQNUM.fetch_add(1, Ordering::Relaxed);
                    netlink::broadcast(
                        NETLINK_KOBJECT_UEVENT,
                        UEVENT_GROUP,
                        &hotplug_payload(seqnum),
                    );
                    info!("display changed to {}x{}", info.width, info.height);
                }
            })
            .expect("failed to spawn the drm hotplug worker");
    });
}

/// The shape udev parses: a summary line, then NUL terminated properties.
fn hotplug_payload(seqnum: u64) -> Vec<u8> {
    let fields: [String; 6] = [
        format!("change@{DEVPATH}"),
        String::from("ACTION=change"),
        format!("DEVPATH={DEVPATH}"),
        String::from("SUBSYSTEM=drm"),
        String::from("HOTPLUG=1"),
        format!("SEQNUM={seqnum}"),
    ];
    let mut payload = Vec::new();
    for field in fields {
        payload.extend_from_slice(field.as_bytes());
        payload.push(0);
    }
    payload
}

#[cfg(all(test, not(axtest)))]
mod tests {
    use super::*;

    #[test]
    fn a_hotplug_uevent_carries_the_drm_device_and_its_action() {
        let payload = hotplug_payload(7);
        let fields: Vec<&str> = payload
            .split(|byte| *byte == 0)
            .filter(|field| !field.is_empty())
            .map(|field| core::str::from_utf8(field).unwrap())
            .collect();
        assert_eq!(fields[0], "change@/devices/virtual/drm/card0");
        assert!(fields.contains(&"ACTION=change"));
        assert!(fields.contains(&"SUBSYSTEM=drm"));
        assert!(fields.contains(&"HOTPLUG=1"));
        assert!(fields.contains(&"SEQNUM=7"));
        assert_eq!(*payload.last().unwrap(), 0);
    }
}
