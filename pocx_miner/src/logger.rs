// Copyright (c) 2025 Proof of Capacity Consortium
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

use crate::config::Cfg;

use log::LevelFilter;
use log4rs::append::console::ConsoleAppender;
use log4rs::append::rolling_file::policy::compound::roll::fixed_window::FixedWindowRoller;
use log4rs::append::rolling_file::policy::compound::trigger::size::SizeTrigger;
use log4rs::append::rolling_file::policy::compound::CompoundPolicy;
use log4rs::append::rolling_file::RollingFileAppender;
use log4rs::config::{Appender, Config, Root};
use log4rs::encode::pattern::PatternEncoder;
use log4rs::filter::threshold::ThresholdFilter;

fn to_log_level(s: &str, default: log::LevelFilter) -> log::LevelFilter {
    match s.to_lowercase().as_str() {
        "trace" => log::LevelFilter::Trace,
        "debug" => log::LevelFilter::Debug,
        "info" => log::LevelFilter::Info,
        "warn" => log::LevelFilter::Warn,
        "error" => log::LevelFilter::Error,
        "off" => log::LevelFilter::Off,
        _ => default,
    }
}

pub fn init_logger(cfg: &Cfg) -> log4rs::Handle {
    let level_console = to_log_level(&cfg.console_log_level, log::LevelFilter::Info);
    let level_logfile = to_log_level(&cfg.logfile_log_level, log::LevelFilter::Warn);
    let mut console_log_pattern = if cfg.show_progress {
        "\r".to_owned()
    } else {
        "".to_owned()
    };
    console_log_pattern.push_str(&cfg.console_log_pattern);
    let mut logfile_log_pattern = if cfg.show_progress {
        "\r".to_owned()
    } else {
        "".to_owned()
    };
    logfile_log_pattern.push_str(&cfg.logfile_log_pattern);

    let stdout = ConsoleAppender::builder()
        .encoder(Box::new(PatternEncoder::new(&console_log_pattern)))
        .build();

    let roller = FixedWindowRoller::builder()
        .base(1)
        .build("log/miner.{}.log", cfg.logfile_max_count)
        .unwrap();
    let trigger = SizeTrigger::new(&cfg.logfile_max_size * 1024 * 1024);
    let policy = Box::new(CompoundPolicy::new(Box::new(trigger), Box::new(roller)));

    let config = if level_logfile == log::LevelFilter::Off {
        Config::builder()
            .appender(
                Appender::builder()
                    .filter(Box::new(ThresholdFilter::new(level_console)))
                    .build("stdout", Box::new(stdout)),
            )
            .build(Root::builder().appender("stdout").build(LevelFilter::Info))
            .unwrap()
    } else {
        let logfile = RollingFileAppender::builder()
            .encoder(Box::new(PatternEncoder::new(&logfile_log_pattern)))
            .build("log/miner.1.log", policy)
            .unwrap();
        Config::builder()
            .appender(
                Appender::builder()
                    .filter(Box::new(ThresholdFilter::new(level_console)))
                    .build("stdout", Box::new(stdout)),
            )
            .appender(
                Appender::builder()
                    .filter(Box::new(ThresholdFilter::new(level_logfile)))
                    .build("logfile", Box::new(logfile)),
            )
            .build(
                Root::builder()
                    .appender("stdout")
                    .appender("logfile")
                    .build(LevelFilter::Trace),
            )
            .unwrap()
    };
    log4rs::init_config(config).unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_to_log_level() {
        assert_eq!(
            to_log_level("Trace", log::LevelFilter::Error),
            log::LevelFilter::Trace
        );
        assert_eq!(
            to_log_level("Foo", log::LevelFilter::Error),
            log::LevelFilter::Error
        );
        assert_eq!(
            to_log_level("DEBUG", log::LevelFilter::Error),
            log::LevelFilter::Debug
        );
        assert_eq!(
            to_log_level("InFo", log::LevelFilter::Error),
            log::LevelFilter::Info
        );
        assert_eq!(
            to_log_level("eRROR", log::LevelFilter::Info),
            log::LevelFilter::Error
        );
        assert_eq!(
            to_log_level("WARN", log::LevelFilter::Info),
            log::LevelFilter::Warn
        );
        assert_eq!(
            to_log_level("Off", log::LevelFilter::Info),
            log::LevelFilter::Off
        );
    }
}
