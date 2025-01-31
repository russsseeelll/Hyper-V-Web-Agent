use crate::logging::log_message;
use std::process::Command;

pub fn run_powershell(script: &str) -> Result<String, String> {
    log_message(&format!("running powershell script: {}", script));

    let output = Command::new("powershell.exe")
        .arg("-Command")
        .arg(script)
        .output()
        .map_err(|e| format!("failed to start powershell: {}", e))?;

    if output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        Ok(stdout.to_string())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        Err(format!(
            "powershell command failed with status code {:?}.\n{}",
            output.status.code(),
            stderr
        ))
    }
}
