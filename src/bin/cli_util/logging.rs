use clap::ValueEnum;
use simple_logger::SimpleLogger;

pub fn init_logger(level: Verbosity) -> Result<(), log::SetLoggerError> {
    let level = match level {
        Verbosity::Quiet => log::LevelFilter::Off,
        Verbosity::Normal => log::LevelFilter::Error,
        Verbosity::Verbose => log::LevelFilter::Info,
        Verbosity::Debug => log::LevelFilter::Trace,
    };

    SimpleLogger::new()
        .with_level(level)
        .without_timestamps()
        .init()
}

#[derive(Debug, Clone, ValueEnum)]
pub enum Verbosity {
    Quiet,
    Normal,
    Verbose,
    Debug,
}