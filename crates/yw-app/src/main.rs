//! yw-app entry point (spec/04). The binary only enters; logic lives in the library.
#![windows_subsystem = "windows"]
#![forbid(unsafe_code)]

use std::process::ExitCode;

fn main() -> ExitCode {
    ExitCode::SUCCESS
}
