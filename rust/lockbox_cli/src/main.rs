#![deny(unsafe_op_in_unsafe_fn)]
#![deny(clippy::undocumented_unsafe_blocks)]

mod commands;
mod secret_prompt;

fn main() {
    if let Err(err) = commands::run() {
        eprintln!("error: {err}");
        std::process::exit(1);
    }
}
