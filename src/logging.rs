// this file provides a simple function to log messages to a log file in the same directory as the executable.

use std::io::Write;

pub fn log_message(msg: &str) {
    if let Ok(mut exe_path) = std::env::current_exe() {
        exe_path.pop();
        exe_path.push("hyperv_agent.log");

        if let Ok(mut file) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&exe_path)
        {
            let _ = writeln!(file, "{}", msg);
        }
    }
}
