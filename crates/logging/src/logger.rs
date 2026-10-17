//! The `log::Log` implementation behind [`crate::install`].

use crate::{component_of, format_lines, FileSink, Filter};
use log::{LevelFilter, Log, Metadata, Record};
use std::time::SystemTime;

pub(crate) struct Logger {
    sink: Option<FileSink>,
    filter: Filter,
}

impl Logger {
    pub(crate) fn new(sink: FileSink, filter: Filter) -> Logger {
        Logger {
            sink: Some(sink),
            filter,
        }
    }

    /// A logger with no sink, for testing the filter.
    #[cfg(test)]
    pub(crate) fn for_test(filter: Filter) -> Logger {
        Logger { sink: None, filter }
    }

    /// The most verbose level any component may log at.
    pub(crate) fn max_level(&self) -> LevelFilter {
        self.filter
            .per_component
            .iter()
            .map(|(_, l)| *l)
            .fold(self.filter.default, |a, b| a.max(b))
    }

    fn limit_for(&self, component: &str) -> LevelFilter {
        self.filter
            .per_component
            .iter()
            .find(|(c, _)| c == component)
            .map(|(_, l)| *l)
            .unwrap_or(self.filter.default)
    }
}

impl Log for Logger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        metadata.level() <= self.limit_for(component_of(metadata.target()))
    }

    fn log(&self, record: &Record) {
        if !self.enabled(record.metadata()) {
            return;
        }
        if let Some(sink) = &self.sink {
            let lines = format_lines(
                SystemTime::now(),
                std::process::id(),
                record.level(),
                component_of(record.target()),
                &record.args().to_string(),
            );
            sink.write_lines(&lines);
        }
    }

    fn flush(&self) {}
}
