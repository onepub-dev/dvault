#![deny(unsafe_op_in_unsafe_fn)]
#![deny(clippy::undocumented_unsafe_blocks)]

mod commands;
mod secret_prompt;

fn main() {
    if let Err(err) = commands::run() {
        if let Some(err) = err.downcast_ref::<clap::Error>() {
            if let Err(print_err) = err.print() {
                eprintln!("error: {print_err}");
            }
        } else {
            eprintln!("error: {err}");
        }
        std::process::exit(1);
    }
}
