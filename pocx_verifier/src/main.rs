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
