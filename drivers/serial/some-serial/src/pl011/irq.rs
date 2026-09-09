use super::*;

/// IRQ-only endpoint for a PL011 UART.
pub struct Pl011Irq {
    pub(super) base: Reg,
    pub(super) saved_rx_status: Pl011RxStatus,
}

impl Pl011Irq {
    fn registers(&self) -> &Pl011Registers {
        // SAFETY: `base` points at the mapped PL011 register block. The IRQ
        // endpoint intentionally exposes no FIFO data methods.
        unsafe { &*self.base.0.as_ptr() }
    }
}

/// The register access one interrupt needs, split out so the order of
/// acknowledge and drain can be exercised without a mapped PL011.
pub(super) trait Pl011IrqOps {
    fn masked_status(&self) -> u32;
    fn acknowledge(&mut self, status: u32);
    fn next_rx_sample(&mut self) -> Option<RxSample>;
    fn disable_all_sources(&mut self);
    fn mask_sources(&mut self, sources: SerialEventSet);
}

impl Pl011IrqOps for Pl011Irq {
    fn masked_status(&self) -> u32 {
        self.registers().uartmis.get()
    }

    fn acknowledge(&mut self, status: u32) {
        self.registers().uarticr.set(status);
    }

    fn next_rx_sample(&mut self) -> Option<RxSample> {
        let base = self.base;
        // SAFETY: `base` is the mapped PL011 register block shared with the
        // task endpoint under the runtime's same-CPU exclusion rule.
        let registers = unsafe { &*base.0.as_ptr() };
        read_rx_sample(registers, &mut self.saved_rx_status)
    }

    fn disable_all_sources(&mut self) {
        self.registers().uartimsc.set(0);
    }

    fn mask_sources(&mut self, sources: SerialEventSet) {
        let enabled = self.registers().uartimsc.get();
        self.registers()
            .uartimsc
            .set(enabled & !imsc_for_events(sources));
    }
}

pub(super) fn service_irq<O: Pl011IrqOps>(ops: &mut O) -> Option<SerialIrqReport> {
    let active = ops.masked_status();
    if active == 0 {
        return None;
    }
    let mis = LocalRegisterCopy::<u32, UARTIS::Register>::new(active);

    let mut events = events_from_mis(mis);
    if active & !ALL_IRQ_BITS != 0 {
        events |= SerialEventSet::FAULT;
    }
    let mut rx_errors = rx_errors_from_mis(mis);

    // The TX source is masked before its status is acknowledged, because the
    // level reasserts as soon as the status is cleared and would raise an
    // interrupt this handler has already accounted for.
    let tx_rearm = events & SerialEventSet::TX_SPACE;
    if !tx_rearm.is_empty() && !events.contains(SerialEventSet::FAULT) {
        ops.mask_sources(tx_rearm);
    }

    // Reading the data register is what retires an RX interrupt, so the
    // sampled status is acknowledged before the FIFO is drained. Clearing it
    // afterwards would also clear the interrupt raised by a byte that landed
    // during the drain, stranding that byte in a FIFO nothing wakes up for.
    ops.acknowledge(active);

    let mut rx = IrqRxBatch::new();
    if events.intersects(SerialEventSet::RX) {
        for _ in 0..IRQ_RX_BATCH_CAPACITY {
            let Some(sample) = ops.next_rx_sample() else {
                break;
            };
            rx_errors |= rx_errors_from_sample(sample);
            rx.try_push(sample)
                .expect("the fixed PL011 IRQ loop cannot overflow its RX batch");
        }
    }

    let mut rearm = tx_rearm;
    if rx.len() == IRQ_RX_BATCH_CAPACITY || rx_errors.contains(RxErrorFlags::OVERRUN) {
        rearm |= SerialEventSet::RX;
    }
    if events.contains(SerialEventSet::FAULT) {
        ops.disable_all_sources();
    } else if rearm.intersects(SerialEventSet::RX) {
        ops.mask_sources(SerialEventSet::RX);
    }

    Some(SerialIrqReport::new(
        SerialIrqEvent {
            events,
            rx_errors,
            rearm,
        },
        rx,
    ))
}

impl UartIrq for Pl011Irq {
    fn mask(&mut self, sources: SerialEventSet) {
        self.mask_sources(sources);
    }

    fn handle(&mut self) -> Option<SerialIrqReport> {
        service_irq(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const RX_STATUS: u32 = UARTIS::RX::SET.value | UARTIS::RT::SET.value;
    const FIFO_DEPTH: usize = 16;

    struct FakePl011 {
        status: u32,
        fifo: [u8; FIFO_DEPTH],
        head: usize,
        len: usize,
        late_arrival: Option<u8>,
        masked: SerialEventSet,
        acknowledged: bool,
        tx_masked_before_acknowledge: bool,
    }

    impl FakePl011 {
        fn new(buffered: &[u8], late_arrival: Option<u8>) -> Self {
            let mut fake = Self {
                status: RX_STATUS,
                fifo: [0; FIFO_DEPTH],
                head: 0,
                len: 0,
                late_arrival,
                masked: SerialEventSet::empty(),
                acknowledged: false,
                tx_masked_before_acknowledge: false,
            };
            for &byte in buffered {
                fake.push(byte);
            }
            fake
        }

        fn push(&mut self, byte: u8) {
            let tail = (self.head + self.len) % FIFO_DEPTH;
            self.fifo[tail] = byte;
            self.len += 1;
        }

        fn pop(&mut self) -> u8 {
            let byte = self.fifo[self.head];
            self.head = (self.head + 1) % FIFO_DEPTH;
            self.len -= 1;
            byte
        }
    }

    impl Pl011IrqOps for FakePl011 {
        fn masked_status(&self) -> u32 {
            self.status
        }

        fn acknowledge(&mut self, status: u32) {
            self.acknowledged = true;
            self.status &= !status;
        }

        fn next_rx_sample(&mut self) -> Option<RxSample> {
            if self.len == 0 {
                if let Some(byte) = self.late_arrival.take() {
                    self.push(byte);
                    self.status |= RX_STATUS;
                }
                return None;
            }
            let byte = self.pop();
            Some(RxSample {
                byte: Some(byte),
                flag: RxFlag::Normal,
                overrun: false,
            })
        }

        fn disable_all_sources(&mut self) {
            self.status = 0;
        }

        fn mask_sources(&mut self, sources: SerialEventSet) {
            if sources.contains(SerialEventSet::TX_SPACE) && !self.acknowledged {
                self.tx_masked_before_acknowledge = true;
            }
            self.masked |= sources;
        }
    }

    fn fake_service(fake: &mut FakePl011) -> SerialIrqReport {
        service_irq(fake).expect("a masked status must be serviced")
    }

    #[test]
    fn a_byte_arriving_during_the_drain_keeps_its_interrupt_asserted() {
        let mut fake = FakePl011::new(b"abc", Some(b'd'));

        let report = fake_service(&mut fake);

        assert_eq!(report.rx.as_slice().len(), 3);
        assert_eq!(fake.len, 1, "the late byte stays queued for the next pass");
        assert_ne!(
            fake.status & RX_STATUS,
            0,
            "acknowledging after the drain would clear the late byte's interrupt and leave it \
             stranded in the FIFO"
        );
    }

    #[test]
    fn a_quiet_fifo_leaves_no_interrupt_asserted() {
        let mut fake = FakePl011::new(b"hi", None);

        let report = fake_service(&mut fake);

        assert_eq!(report.rx.as_slice().len(), 2);
        assert_eq!(fake.len, 0);
        assert_eq!(fake.status & RX_STATUS, 0);
        assert!(report.event.rearm.is_empty());
    }

    #[test]
    fn the_tx_source_is_masked_before_its_status_is_acknowledged() {
        let mut fake = FakePl011::new(b"z", None);
        fake.status |= UARTIS::TX::SET.value;

        let report = fake_service(&mut fake);

        assert!(report.event.rearm.contains(SerialEventSet::TX_SPACE));
        assert!(fake.masked.contains(SerialEventSet::TX_SPACE));
        assert!(
            fake.tx_masked_before_acknowledge,
            "clearing TX status first lets the level reassert and raise an interrupt this handler \
             already accounted for"
        );
    }

    #[test]
    fn an_idle_status_is_not_reported_as_an_interrupt() {
        let mut fake = FakePl011::new(b"", None);
        fake.status = 0;

        assert!(service_irq(&mut fake).is_none());
    }
}
