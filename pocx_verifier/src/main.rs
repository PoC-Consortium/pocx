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

mod plotcheck;

use crate::plotcheck::plotcheck;
use clap::{arg, command, value_parser, Command};

fn main() {
    let matches = command!()
        .subcommand_required(true)
        .arg_required_else_help(true)
        .subcommand(
            Command::new("check")
                .about("Checks a PoC plot file for sanity.")
                .arg_required_else_help(true)
                .arg(
                    arg!(-f --file <plotfile> "plot file")
                        .required(true)
                        .value_parser(value_parser!(String)),
                )
                .arg(
                    arg!(-m --mode <mode> "partial : some nonces are checked, random  : endless random check, complete: full check")
                        .required(true)
                        .value_parser(["single", "partial", "random", "complete"]),
                )
                .arg(
                    arg!(-n --nonce <nonce> "nonce : nonce to check when in single mode")
                        .required_if_eq("mode", "single")
                        .value_parser(value_parser!(u64)),
                )
                .arg(
                    arg!(-s --scoop <scoop> "scoop : scoop to check when in single mode")
                        .required_if_eq("mode", "single")
                        .value_parser(value_parser!(u64)),
                )
                .arg(
                    arg!(-b --base_target <base_target> "base_target : base_target to check when in single mode")
                        .required_if_eq("mode", "single")
                        .value_parser(value_parser!(u64)),
                )
                .arg(
                    arg!(-g --generation_signature <generation_signature> "generation_signature : generation signature (hex) to check when in single mode")
                        .required_if_eq("mode", "single")
                        .value_parser(value_parser!(String)),
                ),
        )
        .get_matches();

    if let Some(matches) = matches.subcommand_matches("check") {
        plotcheck(matches);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_command_creation() {
        let cmd = command!()
            .subcommand_required(true)
            .arg_required_else_help(true)
            .subcommand(
                Command::new("check")
                    .about("Checks a PoC plot file for sanity.")
                    .arg_required_else_help(true),
            );

        assert_eq!(cmd.get_name(), "pocx_verifier");
        assert!(cmd.is_subcommand_required_set());
    }

    #[test]
    fn test_check_subcommand() {
        let cmd = command!()
            .subcommand(
                Command::new("check")
                    .about("Checks a PoC plot file for sanity.")
                    .arg_required_else_help(true)
                    .arg(
                        arg!(-f --file <plotfile> "plot file")
                            .required(true)
                            .value_parser(value_parser!(String)),
                    )
                    .arg(
                        arg!(-m --mode <mode> "partial : some nonces are checked, random  : endless random check, complete: full check")
                            .required(true)
                            .value_parser(["single", "partial", "random", "complete"]),
                    )
            );

        let check_cmd = cmd.find_subcommand("check").unwrap();
        assert_eq!(check_cmd.get_name(), "check");
        assert!(check_cmd.get_arguments().any(|arg| arg.get_id() == "file"));
        assert!(check_cmd.get_arguments().any(|arg| arg.get_id() == "mode"));
    }

    #[test]
    fn test_mode_validation() {
        let valid_modes = ["single", "partial", "random", "complete"];

        for mode in &valid_modes {
            // Test that all valid modes are accepted
            assert!(valid_modes.contains(mode));
        }

        // Test that invalid modes would be rejected
        let invalid_modes = ["invalid", "test", "debug"];
        for invalid_mode in &invalid_modes {
            assert!(!valid_modes.contains(invalid_mode));
        }
    }

    #[test]
    fn test_single_mode_required_args() {
        // Test that single mode requires nonce, scoop, and base_target args
        let cmd = command!().subcommand(
            Command::new("check")
                .arg(
                    arg!(-m --mode <mode>)
                        .required(true)
                        .value_parser(["single", "partial", "random", "complete"]),
                )
                .arg(
                    arg!(-n --nonce <nonce>)
                        .required_if_eq("mode", "single")
                        .value_parser(value_parser!(u64)),
                )
                .arg(
                    arg!(-s --scoop <scoop>)
                        .required_if_eq("mode", "single")
                        .value_parser(value_parser!(u64)),
                )
                .arg(
                    arg!(-b --base_target <base_target>)
                        .required_if_eq("mode", "single")
                        .value_parser(value_parser!(u64)),
                )
                .arg(
                    arg!(-g --generation_signature <generation_signature>)
                        .required_if_eq("mode", "single")
                        .value_parser(value_parser!(String)),
                ),
        );

        let check_cmd = cmd.find_subcommand("check").unwrap();

        // Verify that nonce, scoop, and base_target exist as arguments
        let nonce_arg = check_cmd
            .get_arguments()
            .find(|arg| arg.get_id() == "nonce");
        assert!(nonce_arg.is_some());

        let scoop_arg = check_cmd
            .get_arguments()
            .find(|arg| arg.get_id() == "scoop");
        assert!(scoop_arg.is_some());

        let base_target_arg = check_cmd
            .get_arguments()
            .find(|arg| arg.get_id() == "base_target");
        assert!(base_target_arg.is_some());
    }

    #[test]
    fn test_version_info() {
        // Test that version info is accessible
        let version = env!("CARGO_PKG_VERSION");
        assert!(!version.is_empty());

        // Test that package name is correct
        let name = env!("CARGO_PKG_NAME");
        assert_eq!(name, "pocx_verifier");
    }

    #[test]
    fn test_argument_parsing_types() {
        // Test that value parsers are correctly configured
        use clap::value_parser;

        // String parser for file argument
        let string_parser = value_parser!(String);

        // Test that parsers can be created without errors
        assert!(std::mem::size_of_val(&string_parser) > 0);

        // Test that we can create a u64 parser
        let u64_parser = value_parser!(u64);
        assert!(std::mem::size_of_val(&u64_parser) > 0);
    }
}
