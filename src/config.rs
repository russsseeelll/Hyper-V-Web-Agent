// this file handles the config for the agent.

use crate::logging::log_message;
use crate::powershell::run_powershell;
use openssl::ssl::{SslAcceptor, SslFiletype, SslMethod};
use serde::{Deserialize, Serialize};
use std::io::{self, BufRead, Write};
use std::path::PathBuf;
use std::process::Command;

#[derive(Debug, Serialize, Deserialize, Clone)]
// the config struct stores configuration options that the agent reads
pub struct AgentConfig {
    pub ethernet_switch: String,
    pub iso_directory: String,
    pub default_vhd_directory: String,
    pub port: Option<u16>,
    pub ssl_certificate_path: Option<String>,
    pub ssl_certificate_key_path: Option<String>,
    pub allowed_hosts: Vec<String>,
}

// returns the file path for the config
fn config_file_path() -> PathBuf {
    let mut path = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("."));
    path.pop();
    path.push("hyperv_agent_config.json");
    path
}

// loads the config from the file if it exists, or creates one if not
pub fn load_or_create_config() -> AgentConfig {
    let path = config_file_path();
    if path.exists() {
        match std::fs::read_to_string(&path) {
            Ok(content) => {
                if let Ok(cfg) = serde_json::from_str::<AgentConfig>(&content) {
                    cfg
                } else {
                    println!("config file is corrupt. recreating...");
                    create_config_interactively()
                }
            }
            Err(_) => {
                println!("unable to read config file. recreating...");
                create_config_interactively()
            }
        }
    } else {
        println!("no config file found. let's create one...");
        create_config_interactively()
    }
}

// runs a powershell script to get the list of switch names. returns a vector of switch names
fn get_hyperv_switch_names() -> Vec<String> {
    let script = r#"Get-VMSwitch | Select-Object -ExpandProperty Name"#;
    match run_powershell(script) {
        Ok(output) => output
            .lines()
            .map(|l| l.trim().to_string())
            .filter(|l| !l.is_empty())
            .collect(),
        Err(_) => {
            println!("could not list vswitches (are you running as administrator?).");
            Vec::new()
        }
    }
}

// checks if the process is running with admin privileges
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

// allows the user to pick a switch  from the list of availible ones
fn pick_switch_interactively() -> String {
    let mut switches = get_hyperv_switch_names();
    switches.insert(0, "none".to_string());

    println!("available hyper-v switches:");
    for (i, switch) in switches.iter().enumerate() {
        println!("  {}: {}", i, switch);
    }
    print!("enter the number corresponding to your desired network adapter [default 0]: ");
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
            println!("invalid selection. defaulting to 'none'.");
            "none".to_string()
        }
    }
}

// tests the provided ssl certificate and key files to make sure theyre valid
fn test_ssl_files(cert_path: &str, key_path: &str) -> Result<(), String> {
    let mut builder = SslAcceptor::mozilla_modern(SslMethod::tls())
        .map_err(|e| format!("error creating ssl acceptor builder: {}", e))?;

    builder
        .set_private_key_file(key_path, SslFiletype::PEM)
        .map_err(|e| format!("error setting private key file '{}': {}", key_path, e))?;

    builder.set_certificate_chain_file(cert_path).map_err(|e| {
        format!(
            "error setting certificate chain file '{}': {}",
            cert_path, e
        )
    })?;

    Ok(())
}

// interactively creates a new config
pub fn create_config_interactively() -> AgentConfig {
    let stdin = io::stdin();

    println!("enter the iso directory path (e.g. c:\\isos):");
    let mut iso_dir = String::new();
    stdin.lock().read_line(&mut iso_dir).unwrap();
    let iso_dir = if iso_dir.trim().is_empty() {
        "C:\\ISOs".to_string()
    } else {
        iso_dir.trim().to_string()
    };

    println!("enter the default vhdx directory (e.g. c:\\vms):");
    let mut vhd_dir = String::new();
    stdin.lock().read_line(&mut vhd_dir).unwrap();
    let vhd_dir = if vhd_dir.trim().is_empty() {
        "C:\\VMs".to_string()
    } else {
        vhd_dir.trim().to_string()
    };

    println!("enter the port number to listen on (blank for default 7623):");
    let mut port_str = String::new();
    stdin.lock().read_line(&mut port_str).unwrap();
    let port = if port_str.trim().is_empty() {
        None
    } else {
        match port_str.trim().parse::<u16>() {
            Ok(parsed_port) => Some(parsed_port),
            Err(_) => {
                println!("invalid port specified. defaulting to 7623.");
                None
            }
        }
    };

    println!("enter the path to an ssl certificate file (blank to skip):");
    let mut cert_path_input = String::new();
    stdin.lock().read_line(&mut cert_path_input).unwrap();
    let cert_path = if cert_path_input.trim().is_empty() {
        None
    } else {
        Some(cert_path_input.trim().to_string())
    };

    println!("enter the path to an ssl private key file (blank to skip):");
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
                println!("certificate and key appear valid.");
            }
            Err(e) => {
                println!("warning: ssl files appear invalid.\n{}", e);
                println!("press enter to continue or ctrl+c to abort...");
                let _ = io::stdin().read_line(&mut String::new());
            }
        }
    }

    // ask if the user wants to restrict api access to specific hosts
    loop {
        print!("do you want to restrict api access to specific hosts? (y/n): ");
        io::stdout().flush().unwrap();
        let mut restrict_choice = String::new();
        stdin.lock().read_line(&mut restrict_choice).unwrap();
        let restrict_choice = restrict_choice.trim().to_lowercase();
        if restrict_choice == "y"
            || restrict_choice == "yes"
            || restrict_choice == "n"
            || restrict_choice == "no"
        {
            let allowed_hosts = if restrict_choice == "y" || restrict_choice == "yes" {
                println!("enter allowed hosts (dns names or ip addresses), one per line. enter an empty line to finish:");
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

            // ask the user to pick a hyper-v switch.
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
            println!("invalid input. please enter 'y' or 'n'.");
        }
    }
}

// saves the provided configuration to a file in json format.
pub fn save_config(cfg: &AgentConfig) {
    let path = config_file_path();
    let json_str = serde_json::to_string_pretty(cfg).unwrap();
    let _ = std::fs::write(&path, json_str);

    println!("created config file at \"{}\"", path.display());
    log_message(&format!("created config file at \"{}\"", path.display()));
}
