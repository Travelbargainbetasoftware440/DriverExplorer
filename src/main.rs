#![warn(dead_code)]
mod drivers;
mod services;
mod cli;
mod gui;
mod export;

use std::env;

fn main() {
    let args: Vec<String> = env::args().collect();

    // Determine mode: GUI if no arguments, CLI otherwise
    let is_gui_mode = args.len() == 1;

    if is_gui_mode {
        // Run GUI (console window will be hidden by manifest)
        if let Err(e) = gui::run() {
            eprintln!("GUI error: {}", e);
            std::process::exit(1);
        }
    } else {
        if let Err(e) = cli::run() {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    }
}
