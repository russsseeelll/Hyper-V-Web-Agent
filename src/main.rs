use actix_web::{get, post, web, App, HttpResponse, HttpServer, Responder};
use serde::{Deserialize, Serialize};
use regex::Regex;
use std::io::{Write, BufRead};
use std::path::PathBuf;
use std::process::Command;
use crossterm::{
    cursor,
    event::{read, Event, KeyCode, KeyEvent},
    terminal, ExecutableCommand,
};

/// Log messages to `hyperv_agent.log` in the same folder as the .exe
fn log_message(msg: &str) {
    if let Ok(mut exe_path) = std::env::current_exe() {
        exe_path.pop();
        exe_path.push("hyperv_agent.log");

        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&exe_path);

        if let Ok(ref mut f) = file {
            let _ = writeln!(f, "{}", msg);
        }
    }
}

/// The config stores only the vSwitch and the ISO directory, as requested.
#[derive(Debug, Serialize, Deserialize, Clone)]
struct AgentConfig {
    ethernet_switch: String,
    iso_directory: String,
    default_vhd_directory: String,
}

/// Path to `hyperv_agent_config.json` in the same folder as the .exe
fn config_file_path() -> PathBuf {
    let mut path = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("."));
    path.pop();
    path.push("hyperv_agent_config.json");
    path
}

/// Load an existing config or create it by prompting the user.
fn load_or_create_config() -> AgentConfig {
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

/// Fetches all vSwitch names via PowerShell, returning a vector of names.
/// If we cannot fetch or if there are none, returns an empty vector.
fn get_hyperv_switch_names() -> Vec<String> {
    let script = r#"Get-VMSwitch | Select-Object -ExpandProperty Name"#;
    let ps_result = run_powershell(script);

    match ps_result {
        Ok(output) => {
            // Split by lines
            let lines: Vec<String> = output
                .lines()
                .map(|l| l.trim().to_string())
                .filter(|l| !l.is_empty())
                .collect();
            lines
        }
        Err(_) => {
            println!("Could not list vSwitches (are you running as Administrator?).");
            Vec::new()
        }
    }
}

fn running_as_admin() -> bool {
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

/// Prompts user to pick a switch from the list or "0" for none.
fn pick_switch_interactively() -> String {
    // First, get the list of switches from PowerShell
    let switches = get_hyperv_switch_names();
    let mut menu_items = Vec::new();
    // If we found none, default to "none"
    if switches.is_empty() {
        println!("No vSwitches detected (or insufficient privileges). Defaulting to 'none'.");
        return "none".to_string();
    }
    // Build a list: if we have [ "Default Switch", "External" ], we create:
    // menu_items = [ "none", "Default Switch", "External" ]
    menu_items.push("none".to_string());
    menu_items.extend(switches);

    // We'll track the currently highlighted index
    let mut selected_idx: usize = 0;

    // Enter raw mode so we can read arrow keys
    let _ = std::io::stdout().execute(terminal::EnterAlternateScreen);
    let _ = crossterm::terminal::enable_raw_mode();

    loop {
        // Clear screen
        let _ = std::io::stdout().execute(terminal::Clear(terminal::ClearType::All));
        let _ = std::io::stdout().execute(cursor::MoveTo(0, 0));

        println!("Available Hyper-V switches:");
        for (i, item) in menu_items.iter().enumerate() {
            if i == selected_idx {
                // highlight this item
                println!("  > {}", item);
            } else {
                println!("    {}", item);
            }
        }
        println!();
        println!("Use UP/DOWN arrow keys to select, ENTER to confirm.");

        // Read an event
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
                    KeyCode::Enter => {
                        // finalize choice
                        break;
                    }
                    KeyCode::Esc => {
                        // if user presses ESC, we choose "none"
                        selected_idx = 0;
                        break;
                    }
                    _ => {}
                },
                _ => {}
            }
        }
    }

    // Clean up terminal
    let _ = crossterm::terminal::disable_raw_mode();
    let _ = std::io::stdout().execute(terminal::LeaveAlternateScreen);

    // Return the chosen switch
    menu_items[selected_idx].clone()
}
/// Interactive config creation. If running as a service with no console, this won't work.
fn create_config_interactively() -> AgentConfig {

    let chosen_switch = pick_switch_interactively();

    let stdin = std::io::stdin();
    println!("Enter the ISO directory path (e.g. C:\\ISOs):");
    let mut iso_dir = String::new();
    stdin.lock().read_line(&mut iso_dir).unwrap();
    let iso_dir = iso_dir.trim();
    let iso_dir = if iso_dir.is_empty() {
        "C:\\ISOs"
    } else {
        iso_dir
    };

    println!("Enter the default VHDX directory (e.g. C:\\VMs):");
    let mut vhd_dir = String::new();
    stdin.lock().read_line(&mut vhd_dir).unwrap();
    let vhd_dir = vhd_dir.trim();
    let vhd_dir = if vhd_dir.is_empty() {
        "C:\\VMs"
    } else {
        vhd_dir
    };

    let config = AgentConfig {
        ethernet_switch: chosen_switch,
        iso_directory: iso_dir.to_string(),
        default_vhd_directory: vhd_dir.to_string(),
    };

    save_config(&config);
    config
}

/// Save config to disk
fn save_config(cfg: &AgentConfig) {
    let path = config_file_path();
    let json_str = serde_json::to_string_pretty(cfg).unwrap();
    // Write the file
    let _ = std::fs::write(&path, json_str);


    println!("Created config file at \"{}\"", path.display());
    log_message(&format!("Created config file at \"{}\"", path.display()));
}

/// ===============================
/// Definition of All Agent Commands
/// ===============================
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
enum HyperVCommand {
    CreateVm {
        vm_name: String,
        memory_bytes: u64,
        generation: u8,
        cpu_count: Option<u32>,
        vhd_path: Option<String>,
        vhd_size_bytes: u64,
    },

    SetVmProcessor {
        vm_name: String,
        cpu_count: u32,
    },
    SetStaticMac {
        vm_name: String,
        mac_address: String,
    },
    EnableDynamicMemory {
        vm_name: String,
    },
    DisableDynamicMemory {
        vm_name: String,
    },
    CreateVhd {
        file_path: String,
        size_bytes: u64,
    },
    AttachVhd {
        vm_name: String,
        file_path: String,
    },
    DetachVhd {
        vm_name: String,
        controller_type: String,
        controller_number: u8,
        controller_location: u8,
    },
    AttachIso {
        vm_name: String,
        iso_path: String,
    },
    StartVm {
        vm_name: String,
    },
    StopVm {
        vm_name: String,
    },
    RebootVm {
        vm_name: String,
    },
    DeleteVm {
        vm_name: String,
    },
    SetStartupMemory {
        vm_name: String,
        memory_bytes: u64,
    },
    CreateCheckpoint {
        vm_name: String,
        checkpoint_name: String,
    },
    RevertCheckpoint {
        vm_name: String,
        checkpoint_name: String,
    },
    RemoveCheckpoint {
        vm_name: String,
        checkpoint_name: String,
    },
    ListCheckpoints {
        vm_name: String,
    },
    GetVmInfo {
        vm_name: String,
    },
    GetVmMemory {
        vm_name: String,
    },
    RenameVm {
        old_vm_name: String,
        new_vm_name: String,
    },
    ExportVm {
        vm_name: String,
        export_path: String,
    },
    TestCommand {
        message: String,
    },
}

#[derive(Debug, Deserialize)]
struct CommandRequest {
    command: HyperVCommand,
}

// ===========================
//  Validation for Each Field
// ===========================
fn validate_vm_name(name: &str) -> Result<(), String> {
    let re = Regex::new(r"^[A-Za-z0-9_\-]{1,64}$").unwrap();
    if re.is_match(name) {
        Ok(())
    } else {
        Err(format!("Invalid VM name: {}", name))
    }
}

fn validate_mac_address(mac: &str) -> Result<(), String> {
    let re = Regex::new(r"^[0-9A-Fa-f]{2}(-[0-9A-Fa-f]{2}){5}$").unwrap();
    if re.is_match(mac) {
        Ok(())
    } else {
        Err(format!("Invalid MAC address: {}", mac))
    }
}

fn validate_checkpoint_name(name: &str) -> Result<(), String> {
    let re = Regex::new(r"^[A-Za-z0-9_\-]{1,64}$").unwrap();
    if re.is_match(name) {
        Ok(())
    } else {
        Err(format!("Invalid checkpoint name: {}", name))
    }
}

fn validate_file_path(path: &str) -> Result<(), String> {
    if path.contains('|') || path.is_empty() {
        return Err(format!("Invalid file path: {}", path));
    }
    Ok(())
}

fn validate_generation(gen: u8) -> Result<(), String> {
    match gen {
        1 | 2 => Ok(()),
        _ => Err(format!("Invalid VM generation: {}", gen)),
    }
}

fn validate_cpu_count(count: u32) -> Result<(), String> {
    if count == 0 || count > 64 {
        return Err(format!("CPU count out of range: {}", count));
    }
    Ok(())
}

fn validate_memory_bytes(bytes: u64) -> Result<(), String> {
    if bytes < 512_000_000 {
        return Err(format!(
            "Memory bytes too low (min ~512MB recommended): {}",
            bytes
        ));
    }
    if bytes > 1_000_000_000_000 {
        return Err(format!(
            "Memory bytes too large (>1TB not allowed in this example): {}",
            bytes
        ));
    }
    Ok(())
}

fn validate_command(cmd: &HyperVCommand) -> Result<(), String> {
    match cmd {
        HyperVCommand::CreateVm {
            vm_name,
            memory_bytes,
            generation,
            cpu_count,
            vhd_path,
            vhd_size_bytes,
        } => {
            validate_vm_name(vm_name)?;
            validate_memory_bytes(*memory_bytes)?;
            validate_generation(*generation)?;

            if let Some(c) = cpu_count {
                validate_cpu_count(*c)?;
            }

            validate_memory_bytes(*vhd_size_bytes)?;

            if let Some(path) = vhd_path {
                validate_file_path(path)?;
            }

            Ok(())
        }
        HyperVCommand::SetVmProcessor { vm_name, cpu_count } => {
            validate_vm_name(vm_name)?;
            validate_cpu_count(*cpu_count)
        }
        HyperVCommand::SetStaticMac {
            vm_name,
            mac_address,
        } => {
            validate_vm_name(vm_name)?;
            validate_mac_address(mac_address)
        }
        HyperVCommand::EnableDynamicMemory { vm_name }
        | HyperVCommand::DisableDynamicMemory { vm_name } => validate_vm_name(vm_name),
        HyperVCommand::CreateVhd {
            file_path,
            size_bytes,
        } => {
            validate_file_path(file_path)?;
            validate_memory_bytes(*size_bytes)
        }
        HyperVCommand::AttachVhd {
            vm_name,
            file_path,
        } => {
            validate_vm_name(vm_name)?;
            validate_file_path(file_path)
        }
        HyperVCommand::DetachVhd {
            vm_name,
            controller_type,
            controller_number,
            controller_location,
        } => {
            validate_vm_name(vm_name)?;
            if !["IDE", "SCSI"].contains(&controller_type.as_str()) {
                return Err(format!("Invalid controller type: {}", controller_type));
            }
            if *controller_number > 3 {
                return Err(format!("Invalid controller number: {}", controller_number));
            }
            if *controller_location > 64 {
                return Err(format!("Invalid controller location: {}", controller_location));
            }
            Ok(())
        }
        HyperVCommand::AttachIso { vm_name, iso_path } => {
            validate_vm_name(vm_name)?;
            validate_file_path(iso_path)
        }
        HyperVCommand::StartVm { vm_name }
        | HyperVCommand::StopVm { vm_name }
        | HyperVCommand::RebootVm { vm_name }
        | HyperVCommand::DeleteVm { vm_name }
        | HyperVCommand::ListCheckpoints { vm_name }
        | HyperVCommand::GetVmInfo { vm_name }
        | HyperVCommand::GetVmMemory { vm_name } => validate_vm_name(vm_name),
        HyperVCommand::SetStartupMemory {
            vm_name,
            memory_bytes,
        } => {
            validate_vm_name(vm_name)?;
            validate_memory_bytes(*memory_bytes)
        }
        HyperVCommand::CreateCheckpoint {
            vm_name,
            checkpoint_name,
        }
        | HyperVCommand::RevertCheckpoint {
            vm_name,
            checkpoint_name,
        }
        | HyperVCommand::RemoveCheckpoint {
            vm_name,
            checkpoint_name,
        } => {
            validate_vm_name(vm_name)?;
            validate_checkpoint_name(checkpoint_name)
        }
        HyperVCommand::RenameVm {
            old_vm_name,
            new_vm_name,
        } => {
            validate_vm_name(old_vm_name)?;
            validate_vm_name(new_vm_name)
        }
        HyperVCommand::ExportVm {
            vm_name,
            export_path,
        } => {
            validate_vm_name(vm_name)?;
            validate_file_path(export_path)
        }
        HyperVCommand::TestCommand { message } => {
            if message.is_empty() {
                return Err("Test message cannot be empty".to_string());
            }
            Ok(())
        }
    }
}

/// POST /execute
#[post("/execute")]
async fn execute_command(
    req: web::Json<CommandRequest>,
    data: web::Data<AgentConfig>,
) -> impl Responder {
    log_message(&format!("Incoming request: {:?}", req.command));

    if let Err(e) = validate_command(&req.command) {
        let msg = format!("Validation error: {}", e);
        log_message(&msg);
        return HttpResponse::BadRequest().body(msg);
    }

    let config = data.as_ref();
    let command = &req.command;
    let ps_result = match command {
        HyperVCommand::CreateVm {
            vm_name,
            memory_bytes,
            generation,
            cpu_count,
            vhd_path,
            vhd_size_bytes,
        } => {
            // Step 1: Create the VM
            let create_cmd = format!(
                "New-VM -Name {vm} -MemoryStartupBytes {mem} -Generation {gen}",
                vm = vm_name,
                mem = memory_bytes,
                gen = generation
            );

            // Step 2: connect to vSwitch if not "none"
            let connect_cmd = if config.ethernet_switch.to_lowercase() != "none" {
                format!(
                    "Connect-VMNetworkAdapter -VMName {vm} -SwitchName '{sw}'",
                    vm = vm_name,
                    sw = config.ethernet_switch
                )
            } else {
                "".to_string()
            };

            // Step 3: optional CPU
            let cpu_cmd = if let Some(c) = cpu_count {
                if *c > 1 {
                    format!("Set-VMProcessor -VMName {vm} -Count {cnt}", vm = vm_name, cnt = c)
                } else {
                    "".to_string()
                }
            } else {
                "".to_string()
            };

            // Step 4: Build the final VHD path
            let final_vhd_path = if let Some(ref path) = vhd_path {
                path.clone()
            } else {
                format!("{}\\{}.vhdx", config.default_vhd_directory, vm_name)
            };

            // Step 5: Always create and attach the disk using vhd_size_bytes
            let disk_create_cmd = format!(
                "New-VHD -Path {} -SizeBytes {} -Dynamic",
                final_vhd_path, vhd_size_bytes
            );
            let disk_attach_cmd = format!(
                "Add-VMHardDiskDrive -VMName {vm} -Path {p}",
                vm = vm_name,
                p = final_vhd_path
            );

            // Combine all commands
            let full_script = format!(
                "{create}; {connect}; {cpu}; {disk_create}; {disk_attach};",
                create = create_cmd,
                connect = connect_cmd,
                cpu = cpu_cmd,
                disk_create = disk_create_cmd,
                disk_attach = disk_attach_cmd
            );

            run_powershell(&full_script)
        }

        HyperVCommand::SetVmProcessor { vm_name, cpu_count } => run_powershell(&format!(
            "Set-VMProcessor -VMName {} -Count {}",
            vm_name, cpu_count
        )),
        HyperVCommand::SetStaticMac {
            vm_name,
            mac_address,
        } => run_powershell(&format!(
            "Set-VMNetworkAdapter -VMName {} -StaticMacAddress {}",
            vm_name, mac_address
        )),
        HyperVCommand::EnableDynamicMemory { vm_name } => run_powershell(&format!(
            "Set-VMMemory -VMName {} -DynamicMemoryEnabled $true",
            vm_name
        )),
        HyperVCommand::DisableDynamicMemory { vm_name } => run_powershell(&format!(
            "Set-VMMemory -VMName {} -DynamicMemoryEnabled $false",
            vm_name
        )),
        HyperVCommand::CreateVhd {
            file_path,
            size_bytes,
        } => run_powershell(&format!(
            "New-VHD -Path {} -SizeBytes {} -Dynamic",
            file_path, size_bytes
        )),
        HyperVCommand::AttachVhd {
            vm_name,
            file_path,
        } => run_powershell(&format!(
            "Add-VMHardDiskDrive -VMName {} -Path {}",
            vm_name, file_path
        )),
        HyperVCommand::DetachVhd {
            vm_name,
            controller_type,
            controller_number,
            controller_location,
        } => run_powershell(&format!(
            "Remove-VMHardDiskDrive -VMName {} -ControllerType {} -ControllerNumber {} -ControllerLocation {}",
            vm_name, controller_type, controller_number, controller_location
        )),
        HyperVCommand::AttachIso { vm_name, iso_path } => run_powershell(&format!(
            "Add-VMDvdDrive -VMName {} -Path {}",
            vm_name, iso_path
        )),
        HyperVCommand::StartVm { vm_name } => {
            run_powershell(&format!("Start-VM -Name {}", vm_name))
        }
        HyperVCommand::StopVm { vm_name } => {
            run_powershell(&format!("Stop-VM -Name {} -TurnOff", vm_name))
        }
        HyperVCommand::RebootVm { vm_name } => {
            run_powershell(&format!("Restart-VM -Name {}", vm_name))
        }
        HyperVCommand::DeleteVm { vm_name } => {
            run_powershell(&format!("Remove-VM -Name {} -Force", vm_name))
        }
        HyperVCommand::SetStartupMemory {
            vm_name,
            memory_bytes,
        } => run_powershell(&format!(
            "Set-VMMemory -VMName {} -StartupBytes {}",
            vm_name, memory_bytes
        )),
        HyperVCommand::CreateCheckpoint {
            vm_name,
            checkpoint_name,
        } => run_powershell(&format!(
            "Checkpoint-VM -Name {} -SnapshotName {}",
            vm_name, checkpoint_name
        )),
        HyperVCommand::RevertCheckpoint {
            vm_name,
            checkpoint_name,
        } => run_powershell(&format!(
            "Restore-VMCheckpoint -VMName {} -Name {}",
            vm_name, checkpoint_name
        )),
        HyperVCommand::RemoveCheckpoint {
            vm_name,
            checkpoint_name,
        } => run_powershell(&format!(
            "Remove-VMCheckpoint -VMName {} -Name {} -Confirm:$false",
            vm_name, checkpoint_name
        )),
        HyperVCommand::ListCheckpoints { vm_name } => {
            run_powershell(&format!("Get-VMCheckpoint -VMName {}", vm_name))
        }
        HyperVCommand::GetVmInfo { vm_name } => {
            run_powershell(&format!("Get-VM -Name {}", vm_name))
        }
        HyperVCommand::GetVmMemory { vm_name } => {
            run_powershell(&format!("Get-VMMemory -VMName {}", vm_name))
        }
        HyperVCommand::RenameVm {
            old_vm_name,
            new_vm_name,
        } => run_powershell(&format!(
            "Rename-VM -VMName {} -NewName {}",
            old_vm_name, new_vm_name
        )),
        HyperVCommand::ExportVm {
            vm_name,
            export_path,
        } => run_powershell(&format!("Export-VM -Name {} -Path {}", vm_name, export_path)),
        HyperVCommand::TestCommand { message } => {
            run_powershell(&format!("Write-Output 'Test command says: {}'", message))
        }
    };

    match ps_result {
        Ok(output) => {
            let msg = format!("Success:\n{}", output);
            log_message(&msg);
            HttpResponse::Ok().body(output)
        }
        Err(e) => {
            let msg = format!("Error: {}", e);
            log_message(&msg);
            HttpResponse::InternalServerError().body(e)
        }
    }
}

/// GET /vmstatus
#[get("/vmstatus")]
async fn get_vmstatus() -> impl Responder {
    log_message("GET /vmstatus called.");

    let script = r#"
        Get-VM |
        Select-Object Name,State,CPUUsage,MemoryAssigned |
        ConvertTo-Json -Depth 3
    "#;

    match run_powershell(script) {
        Ok(raw_json) => {
            match serde_json::from_str::<serde_json::Value>(&raw_json) {
                Ok(json_val) => HttpResponse::Ok().json(json_val),
                Err(e) => {
                    let msg = format!(
                        "Could not parse VM data as JSON.\nRaw Output:\n{}\nError:\n{}",
                        raw_json, e
                    );
                    log_message(&msg);
                    HttpResponse::Ok().body(msg)
                }
            }
        }
        Err(e) => {
            let msg = format!("Error retrieving VM status: {}", e);
            log_message(&msg);
            HttpResponse::InternalServerError().body(msg)
        }
    }
}

/// GET /listisos
/// Returns the .iso files in `iso_directory`
#[get("/listisos")]
async fn list_isos(data: web::Data<AgentConfig>) -> impl Responder {
    log_message("GET /listisos called.");
    let config = data.as_ref();
    let path = std::path::Path::new(&config.iso_directory);

    if !path.exists() {
        let msg = format!("ISO directory '{}' does not exist.", &config.iso_directory);
        log_message(&msg);
        return HttpResponse::BadRequest().body(msg);
    }

    let mut iso_files = Vec::new();
    match std::fs::read_dir(path) {
        Ok(entries) => {
            for entry in entries {
                if let Ok(e) = entry {
                    let filename = e.file_name().to_string_lossy().to_string();
                    if filename.to_lowercase().ends_with(".iso") {
                        iso_files.push(filename);
                    }
                }
            }
            HttpResponse::Ok().json(iso_files)
        }
        Err(e) => {
            let msg = format!("Error reading ISO directory: {}", e);
            log_message(&msg);
            HttpResponse::InternalServerError().body(msg)
        }
    }
}

/// Helper to run PowerShell commands
fn run_powershell(script: &str) -> Result<String, String> {
    log_message(&format!("Running PowerShell script: {}", script));

    let output = Command::new("powershell.exe")
        .arg("-Command")
        .arg(script)
        .output()
        .map_err(|e| format!("Failed to start PowerShell: {}", e))?;

    if output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        Ok(stdout.to_string())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        Err(format!(
            "PowerShell command failed with status code {:?}.\n{}",
            output.status.code(),
            stderr
        ))
    }
}

/// Main function: loads config, prints banner, starts server on 7623
#[tokio::main]
async fn main() -> std::io::Result<()> {
    // Banner
    println!("====================================");
    println!(" Hyper-V-Web-Agent");
    println!(" A Rust-based connector for Hyper-V management.");
    println!("====================================");
    println!();

    // 1) Ensure we have admin privileges
    if !running_as_admin() {
        println!("You are not running as Administrator. Please relaunch with admin privileges.");
        // Optionally: prompt for user to press Enter, then exit
        let _ = std::io::stdin().read_line(&mut String::new());
        std::process::exit(1);
    }

    // 2) Load or create config
    let config = load_or_create_config();

    // 3) Show final lines
    println!("Server listening on port 7623. IP: 130.209.253.206");

    // Instead of debug-printing with {:?}, print fields manually to avoid double backslashes:
    println!(
        "Config loaded or created: AgentConfig {{ ethernet_switch: \"{}\", iso_directory: \"{}\" }}",
        config.ethernet_switch, config.iso_directory
    );

    log_message("Hyper-V-Web-Agent starting on port 7623...");

    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(config.clone()))
            .service(execute_command)
            .service(get_vmstatus)
            .service(list_isos)
    })
        .bind(("0.0.0.0", 7623))?
        .run()
        .await
}