//! Opt-in timings for the reproducible performance benchmark. Never logs paths,
//! credentials or file contents. Disabled during ordinary client operation.
use std::{sync::OnceLock, time::Instant};

pub(super) struct Phase(&'static str, Option<Instant>);

impl Phase {
    pub(super) fn start(name: &'static str) -> Self {
        static ENABLED: OnceLock<bool> = OnceLock::new();
        let enabled = *ENABLED.get_or_init(|| {
            std::env::var_os("MYSYNC_BENCH_TIMINGS").is_some_and(|value| value == "1")
        });
        Self(name, enabled.then(Instant::now))
    }
}

impl Drop for Phase {
    fn drop(&mut self) {
        if let Some(start) = self.1 {
            eprintln!(
                "MYSYNC_TIMING {} {:.3}",
                self.0,
                start.elapsed().as_secs_f64() * 1000.0
            );
        }
    }
}
