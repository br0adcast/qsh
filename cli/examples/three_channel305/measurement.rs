//! Native entry through joined cleanup; excludes producer-process CPU.
use serde::Serialize;
use std::time::Instant;

fn cpu_ns(seconds: i64, nanoseconds: i64) -> Result<u64, String> {
    if seconds < 0 || !(0..1_000_000_000).contains(&nanoseconds) {
        return Err("invalid process CPU clock value".into());
    }
    (seconds as u64)
        .checked_mul(1_000_000_000)
        .and_then(|value| value.checked_add(nanoseconds as u64))
        .ok_or_else(|| "process CPU clock overflow".into())
}

fn process_cpu_ns() -> Result<u64, String> {
    let mut value = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: value is a valid writable timespec and the fixed clock has no
    // process-external owner. This clock sums only this process's threads.
    if unsafe { libc::clock_gettime(libc::CLOCK_PROCESS_CPUTIME_ID, &mut value) } != 0 {
        return Err("process CPU clock unavailable".into());
    }
    cpu_ns(value.tv_sec, value.tv_nsec)
}

fn resolution_ns(seconds: i64, nanoseconds: i64) -> Result<u64, String> {
    let resolution = cpu_ns(seconds, nanoseconds)?;
    if resolution == 0 {
        return Err("zero reported process CPU clock resolution".into());
    }
    Ok(resolution)
}

fn process_cpu_resolution_ns() -> Result<u64, String> {
    let mut value = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: value is a valid writable timespec for this fixed clock.
    if unsafe { libc::clock_getres(libc::CLOCK_PROCESS_CPUTIME_ID, &mut value) } != 0 {
        return Err("process CPU clock resolution unavailable".into());
    }
    resolution_ns(value.tv_sec, value.tv_nsec)
}

#[derive(Debug, Serialize)]
pub struct Sample {
    pub process_cpu_ns: u64,
    pub elapsed_ns: u64,
    /// Kernel-reported resolution, not an accuracy or measurement-error bound.
    pub process_cpu_resolution_ns: u64,
}
impl Sample {
    fn between(
        start_cpu: u64,
        end_cpu: u64,
        elapsed_ns: u64,
        resolution: u64,
    ) -> Result<Self, String> {
        Ok(Self {
            process_cpu_ns: end_cpu
                .checked_sub(start_cpu)
                .ok_or("process CPU clock regressed")?,
            elapsed_ns,
            process_cpu_resolution_ns: resolution,
        })
    }
}

pub struct Window {
    cpu: u64,
    elapsed: Instant,
    resolution: u64,
}
impl Window {
    pub fn start() -> Result<Self, String> {
        // Clock samples bracket the monotonic window by two small clock reads.
        let resolution = process_cpu_resolution_ns()?;
        let cpu = process_cpu_ns()?;
        Ok(Self {
            cpu,
            elapsed: Instant::now(),
            resolution,
        })
    }
    pub fn finish(self) -> Result<Sample, String> {
        let elapsed = u64::try_from(self.elapsed.elapsed().as_nanos())
            .map_err(|_| "monotonic measurement overflow")?;
        Sample::between(self.cpu, process_cpu_ns()?, elapsed, self.resolution)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn qualification305_measurement_clock_conversion_is_checked() {
        assert_eq!(cpu_ns(2, 3).unwrap(), 2_000_000_003);
        assert!(cpu_ns(-1, 0).is_err());
        assert!(cpu_ns(0, -1).is_err());
        assert!(cpu_ns(0, 1_000_000_000).is_err());
        assert!(cpu_ns(i64::MAX, 0).is_err());
        assert_eq!(resolution_ns(0, 1).unwrap(), 1);
        assert!(resolution_ns(0, 0).is_err());
        assert!(resolution_ns(-1, 0).is_err());
    }
    #[test]
    fn qualification305_measurement_window_subtracts_actual_counters_without_thresholds() {
        let sample = Sample::between(100, 175, 1000, 1).unwrap();
        assert_eq!(sample.process_cpu_ns, 75);
        assert_eq!(sample.elapsed_ns, 1000);
        assert!(Sample::between(100, 99, 1000, 1).is_err());
    }
    #[test]
    fn qualification305_measurement_real_process_clock_is_available() {
        let before = process_cpu_ns().unwrap();
        let after = process_cpu_ns().unwrap();
        assert!(after >= before);
        let sample = Window::start().unwrap().finish().unwrap();
        let value = serde_json::to_value(sample).unwrap();
        assert!(value["process_cpu_ns"].is_u64());
        assert!(value["elapsed_ns"].is_u64());
        assert!(value["process_cpu_resolution_ns"].as_u64().unwrap() > 0);
    }
}
