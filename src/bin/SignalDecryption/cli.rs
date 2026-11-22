//! Command-line parsing: turns raw arguments into a typed [`Command`].
//!
//! Parsing is isolated here (and unit-tested below) so `main` only ever deals
//! with a validated, structured intent rather than loose strings.

use signal_core::Result;

/// Options for the default decrypt action.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Options {
    /// Explicit path to `config.json` (`-c`); defaults to the platform location.
    pub config_path: Option<String>,
    /// Encrypted key supplied directly (`-k`) instead of read from the config.
    pub encrypted_key: Option<String>,
    /// Whether to also print the underlying key material (`-p`).
    pub print_key: bool,
}

/// A fully parsed invocation of the tool.
#[derive(Debug, PartialEq, Eq)]
pub enum Command {
    /// Print usage and exit.
    Help,
    /// Print the version and exit.
    Version,
    /// Decrypt Signal's key using the given options.
    Decrypt(Options),
}

/// Usage text, shared by `-h`/`--help`.
pub const HELP: &str = "\
Usage: SignalDecryption [options]
Options:
  -h, --help         Show this help message
  -c, --config PATH  Specify the path to the config.json file
  -k, --key KEY      Provide an encrypted key directly
  -p, --print-key    Print the secure storage key material (use with caution)
  --version          Show the tool version
";

impl Command {
    /// Parses `args` (including `argv[0]`) into a [`Command`].
    ///
    /// `--help`/`--version` short-circuit; everything else accumulates into a
    /// [`Command::Decrypt`]. An option missing its value, or an unknown flag, is
    /// an error.
    pub fn parse<I>(args: I) -> Result<Command>
    where
        I: IntoIterator<Item = String>,
    {
        let mut args = args.into_iter();
        let _program = args.next(); // discard argv[0]
        let mut options = Options::default();

        while let Some(arg) = args.next() {
            match arg.as_str() {
                "-h" | "--help" => return Ok(Command::Help),
                "--version" => return Ok(Command::Version),
                "-c" | "--config" => options.config_path = Some(take_value(&mut args, &arg)?),
                "-k" | "--key" => options.encrypted_key = Some(take_value(&mut args, &arg)?),
                "-p" | "--print-key" => options.print_key = true,
                other => return Err(format!("Unknown option: {other}").into()),
            }
        }
        Ok(Command::Decrypt(options))
    }
}

/// Consumes the value that must follow a value-taking flag.
fn take_value<I>(args: &mut I, flag: &str) -> Result<String>
where
    I: Iterator<Item = String>,
{
    args.next()
        .ok_or_else(|| format!("Option '{flag}' requires an argument.").into())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds an argv (program name prepended) from the given flags.
    fn argv(flags: &[&str]) -> Vec<String> {
        std::iter::once("SignalDecryption")
            .chain(flags.iter().copied())
            .map(String::from)
            .collect()
    }

    #[test]
    fn no_args_is_default_decrypt() {
        assert_eq!(
            Command::parse(argv(&[])).unwrap(),
            Command::Decrypt(Options::default())
        );
    }

    #[test]
    fn help_and_version_short_circuit() {
        assert_eq!(Command::parse(argv(&["-h"])).unwrap(), Command::Help);
        assert_eq!(Command::parse(argv(&["--help"])).unwrap(), Command::Help);
        assert_eq!(Command::parse(argv(&["--version"])).unwrap(), Command::Version);
    }

    #[test]
    fn collects_all_decrypt_options() {
        let cmd = Command::parse(argv(&["-c", "/tmp/c.json", "-k", "deadbeef", "-p"])).unwrap();
        assert_eq!(
            cmd,
            Command::Decrypt(Options {
                config_path: Some("/tmp/c.json".into()),
                encrypted_key: Some("deadbeef".into()),
                print_key: true,
            })
        );
    }

    #[test]
    fn long_flags_are_equivalent() {
        let cmd = Command::parse(argv(&["--config", "/x", "--key", "ab", "--print-key"])).unwrap();
        assert_eq!(
            cmd,
            Command::Decrypt(Options {
                config_path: Some("/x".into()),
                encrypted_key: Some("ab".into()),
                print_key: true,
            })
        );
    }

    #[test]
    fn missing_value_is_an_error() {
        assert!(Command::parse(argv(&["-c"])).is_err());
        assert!(Command::parse(argv(&["--key"])).is_err());
    }

    #[test]
    fn unknown_option_is_an_error() {
        assert!(Command::parse(argv(&["--nope"])).is_err());
    }
}
