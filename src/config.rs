use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::process::Command;
use std::io::BufRead;
use crossterm::{
    cursor,
    event::{read, Event, KeyCode, KeyEvent},
    terminal,
    ExecutableCommand,
};
use openssl::ssl::{SslAcceptor, SslFiletype, SslMethod};
use crate::logging::log_message;
use crate::powershell::run_powershell;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AgentConfig {
    pub ethernet_switch: String,
    pub iso_directory: String,
    pub default_vhd_directory: String,
    pub port: Option<u16>,
    pub ssl_certificate_path: Option<String>,
    pub ssl_certificate_key_path: Option<String>,
    pub allowed_hosts: Vec<String>,
}

fn config_file_path() -> PathBuf {
    let mut path = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("."));
    path.pop();
    path.push("hyperv_agent_config.json");
    path
}

pub fn load_or_create_config() -> AgentConfig {
    let path = config_file_path();
    if path.exists() {
        match std::fs::read_to_string(&path) {
            Ok(content) => {
                if let Ok(cfg) = serde_json::from_str::<AgentConfig>(&content) {
                    cfg
                } else {
                    println!("Config file is corrupt. Recreating...");
                    create_config_interactively()
                }
            }
            Err(_) => {
                println!("Unable to read config file. Recreating...");
                create_config_interactively()
            }
        }
    } else {
        println!("No config file found. Let's create one...");
        create_config_interactively()
    }
}

fn get_hyperv_switch_names() -> Vec<String> {
    let script = r#"Get-VMSwitch | Select-Object -ExpandProperty Name"#;
    match run_powershell(script) {
        Ok(output) => {
            output
                .lines()
                .map(|l| l.trim().to_string())
                .filter(|l| !l.is_empty())
                .collect()
        }
        Err(_) => {
            println!("Could not list vswitches (are you running as administrator?).");
            Vec::new()
        }
    }
}

pub fn running_as_admin() -> bool {
    if let Ok(output) = Command::new("powershell.exe")
        .arg("-Command")
        .arg("([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)")
        .output()
    {
        let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
        return stdout == "True";
    }
    false
}

fn pick_switch_interactively() -> String {
    let switches = get_hyperv_switch_names();
    let mut menu_items = Vec::new();
    if switches.is_empty() {
        println!("No vswitches detected (or insufficient privileges). Defaulting to 'none'.");
        return "none".to_string();
    }
    menu_items.push("none".to_string());
    menu_items.extend(switches);

    let mut selected_idx: usize = 0;
    let _ = std::io::stdout().execute(terminal::EnterAlternateScreen);
    let _ = terminal::enable_raw_mode();

    loop {
        let _ = std::io::stdout().execute(terminal::Clear(terminal::ClearType::All));
        let _ = std::io::stdout().execute(cursor::MoveTo(0, 0));

        println!("Available hyper-v switches:");
        for (i, item) in menu_items.iter().enumerate() {
            if i == selected_idx {
                println!("  > {}", item);
            } else {
                println!("    {}", item);
            }
        }
        println!();
        println!("Use up/down arrow keys to select, enter to confirm (esc to default to 'none').");

        if let Ok(ev) = read() {
            match ev {
                Event::Key(KeyEvent { code, .. }) => match code {
                    KeyCode::Up => {
                        if selected_idx > 0 {
                            selected_idx -= 1;
                        }
                    }
                    KeyCode::Down => {
                        if selected_idx < menu_items.len() - 1 {
                            selected_idx += 1;
                        }
                    }
                    KeyCode::Enter => break,
                    KeyCode::Esc => {
                        selected_idx = 0;
                        break;
                    }
                    _ => {}
                },
                _ => {}
            }
        }
    }

    let _ = terminal::disable_raw_mode();
    let _ = std::io::stdout().execute(terminal::LeaveAlternateScreen);

    menu_items[selected_idx].clone()
}

fn test_ssl_files(cert_path: &str, key_path: &str) -> Result<(), String> {
    let mut builder = SslAcceptor::mozilla_modern(SslMethod::tls())
        .map_err(|e| format!("Error creating SSL acceptor builder: {}", e))?;

    builder
        .set_private_key_file(key_path, SslFiletype::PEM)
        .map_err(|e| format!("Error setting private key file '{}': {}", key_path, e))?;

    builder
        .set_certificate_chain_file(cert_path)
        .map_err(|e| format!("Error setting certificate chain file '{}': {}", cert_path, e))?;

    Ok(())
}

pub fn create_config_interactively() -> AgentConfig {
    let chosen_switch = pick_switch_interactively();

    let stdin = std::io::stdin();

    println!("Enter the ISO directory path (e.g. c:\\isos):");
    let mut iso_dir = String::new();
    stdin.lock().read_line(&mut iso_dir).unwrap();
    let iso_dir = iso_dir.trim();
    let iso_dir = if iso_dir.is_empty() {
        "C:\\ISOs"
    } else {
        iso_dir
    };

    println!("Enter the default VHDX directory (e.g. c:\\vms):");
    let mut vhd_dir = String::new();
    stdin.lock().read_line(&mut vhd_dir).unwrap();
    let vhd_dir = vhd_dir.trim();
    let vhd_dir = if vhd_dir.is_empty() {
        "C:\\VMs"
    } else {
        vhd_dir
    };

    println!("Enter the port number to listen on (blank for default 7623):");
    let mut port_str = String::new();
    stdin.lock().read_line(&mut port_str).unwrap();
    let port = if port_str.trim().is_empty() {
        None
    } else {
        match port_str.trim().parse::<u16>() {
            Ok(parsed_port) => Some(parsed_port),
            Err(_) => {
                println!("Invalid port specified. Defaulting to 7623.");
                None
            }
        }
    };

    println!("Enter the path to an SSL certificate file (blank to skip):");
    let mut cert_path_input = String::new();
    stdin.lock().read_line(&mut cert_path_input).unwrap();
    let cert_path = cert_path_input.trim().to_string();
    let cert_path = if cert_path.is_empty() {
        None
    } else {
        Some(cert_path)
    };

    println!("Enter the path to an SSL private key file (blank to skip):");
    let mut key_path_input = String::new();
    stdin.lock().read_line(&mut key_path_input).unwrap();
    let key_path = key_path_input.trim().to_string();
    let key_path = if key_path.is_empty() {
        None
    } else {
        Some(key_path)
    };

    if let (Some(ref cert), Some(ref key)) = (&cert_path, &key_path) {
        match test_ssl_files(cert, key) {
            Ok(_) => {
                println!("Certificate and key appear valid.");
            }
            Err(e) => {
                println!("Warning: SSL files appear invalid.\n{}", e);
                println!("Press enter to continue or Ctrl+C to abort...");
                let _ = std::io::stdin().read_line(&mut String::new());
            }
        }
    }

    // Ask if the user wants to restrict API access to specific hosts.
    println!("Do you want to restrict API access to specific hosts? (y/n):");
    let mut restrict_choice = String::new();
    stdin.lock().read_line(&mut restrict_choice).unwrap();
    let restrict_choice = restrict_choice.trim().to_lowercase();
    let allowed_hosts = if restrict_choice == "y" || restrict_choice == "yes" {
        println!("Enter allowed hosts (DNS names or IP addresses), one per line. Enter an empty line to finish:");
        let mut hosts = Vec::new();
        loop {
            let mut host = String::new();
            stdin.lock().read_line(&mut host).unwrap();
            let host = host.trim().to_string();
            if host.is_empty() {
                break;
            }
            hosts.push(host);
        }
        if hosts.is_empty() {
            println!("Error: You must specify at least one allowed host.");
            std::process::exit(1);
        }
        hosts
    } else {
        println!("Error: API access must be restricted to specific hosts for security reasons.");
        std::process::exit(1);
    };

    let config = AgentConfig {
        ethernet_switch: chosen_switch,
        iso_directory: iso_dir.to_string(),
        default_vhd_directory: vhd_dir.to_string(),
        port,
        ssl_certificate_path: cert_path,
        ssl_certificate_key_path: key_path,
        allowed_hosts,
    };

    save_config(&config);
    config
}

pub fn save_config(cfg: &AgentConfig) {
    let path = config_file_path();
    let json_str = serde_json::to_string_pretty(cfg).unwrap();
    let _ = std::fs::write(&path, json_str);

    println!("Created config file at \"{}\"", path.display());
    log_message(&format!("Created config file at \"{}\"", path.display()));
}
