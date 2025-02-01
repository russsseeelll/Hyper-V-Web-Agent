// config.rs
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::process::Command;
use std::io::{self, BufRead, Write};
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

/// Prompt the user to select a hyper-v switch without clearing the screen.
/// Lists the available switches with numbers and asks the user to enter the corresponding number.
/// If no switches are available, returns "none".
fn pick_switch_interactively() -> String {
    let mut switches = get_hyperv_switch_names();
    // Always allow the user to choose "none".
    switches.insert(0, "none".to_string());

    println!("Available hyper-v switches:");
    for (i, switch) in switches.iter().enumerate() {
        println!("  {}: {}", i, switch);
    }
    print!("Enter the number corresponding to your desired network adapter [default 0]: ");
    io::stdout().flush().unwrap();

    let mut input = String::new();
    let stdin = io::stdin();
    stdin.lock().read_line(&mut input).unwrap();
    let input = input.trim();

    if input.is_empty() {
        return "none".to_string();
    }
    match input.parse::<usize>() {
        Ok(index) if index < switches.len() => switches[index].clone(),
        _ => {
            println!("Invalid selection. Defaulting to 'none'.");
            "none".to_string()
        }
    }
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
    let stdin = io::stdin();

    println!("Enter the ISO directory path (e.g. c:\\isos):");
    let mut iso_dir = String::new();
    stdin.lock().read_line(&mut iso_dir).unwrap();
    let iso_dir = if iso_dir.trim().is_empty() {
        "C:\\ISOs".to_string()
    } else {
        iso_dir.trim().to_string()
    };

    println!("Enter the default VHDX directory (e.g. c:\\vms):");
    let mut vhd_dir = String::new();
    stdin.lock().read_line(&mut vhd_dir).unwrap();
    let vhd_dir = if vhd_dir.trim().is_empty() {
        "C:\\VMs".to_string()
    } else {
        vhd_dir.trim().to_string()
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
    let cert_path = if cert_path_input.trim().is_empty() {
        None
    } else {
        Some(cert_path_input.trim().to_string())
    };

    println!("Enter the path to an SSL private key file (blank to skip):");
    let mut key_path_input = String::new();
    stdin.lock().read_line(&mut key_path_input).unwrap();
    let key_path = if key_path_input.trim().is_empty() {
        None
    } else {
        Some(key_path_input.trim().to_string())
    };

    if let (Some(ref cert), Some(ref key)) = (&cert_path, &key_path) {
        match test_ssl_files(cert, key) {
            Ok(_) => {
                println!("Certificate and key appear valid.");
            }
            Err(e) => {
                println!("Warning: SSL files appear invalid.\n{}", e);
                println!("Press enter to continue or Ctrl+C to abort...");
                let _ = io::stdin().read_line(&mut String::new());
            }
        }
    }

    // Ask if the user wants to restrict API access to specific hosts.
    loop {
        print!("Do you want to restrict API access to specific hosts? (y/n): ");
        io::stdout().flush().unwrap();
        let mut restrict_choice = String::new();
        stdin.lock().read_line(&mut restrict_choice).unwrap();
        let restrict_choice = restrict_choice.trim().to_lowercase();
        if restrict_choice == "y" || restrict_choice == "yes" || restrict_choice == "n" || restrict_choice == "no" {
            // If "y"/"yes", ask for allowed hosts; if "n"/"no", leave empty.
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
                hosts
            } else {
                Vec::new()
            };

            // Now ask for the hyper-v switch selection.
            let chosen_switch = pick_switch_interactively();

            let config = AgentConfig {
                ethernet_switch: chosen_switch,
                iso_directory: iso_dir,
                default_vhd_directory: vhd_dir,
                port,
                ssl_certificate_path: cert_path,
                ssl_certificate_key_path: key_path,
                allowed_hosts,
            };

            save_config(&config);
            return config;
        } else {
            println!("Invalid input. Please enter 'y' or 'n'.");
        }
    }
}

pub fn save_config(cfg: &AgentConfig) {
    let path = config_file_path();
    let json_str = serde_json::to_string_pretty(cfg).unwrap();
    let _ = std::fs::write(&path, json_str);

    println!("Created config file at \"{}\"", path.display());
    log_message(&format!("Created config file at \"{}\"", path.display()));
}
