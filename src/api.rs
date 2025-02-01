// api.rs
use actix_web::{get, post, web, HttpResponse, Responder};
use serde_json;
use crate::commands::{CommandRequest, HyperVCommand};
use crate::config::AgentConfig;
use crate::logging::log_message;
use crate::powershell::run_powershell;
use crate::validation::validate_command;
use std::fs;
use std::path::Path;

#[post("/execute")]
async fn execute_command(
    req: web::Json<CommandRequest>,
    data: web::Data<AgentConfig>,
) -> impl Responder {
    log_message(&format!("incoming request: {:?}", req.command));

    if let Err(e) = validate_command(&req.command) {
        let msg = format!("validation error: {}", e);
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
            let create_cmd = format!(
                "New-VM -Name \"{}\" -MemoryStartupBytes {} -Generation {}",
                vm_name, memory_bytes, generation
            );
            let connect_cmd = if config.ethernet_switch.to_lowercase() != "none" {
                format!(
                    "Connect-VMNetworkAdapter -VMName \"{}\" -SwitchName '{}'",
                    vm_name, config.ethernet_switch
                )
            } else {
                "".to_string()
            };
            let cpu_cmd = if let Some(c) = cpu_count {
                if *c > 1 {
                    format!("Set-VMProcessor -VMName \"{}\" -Count {}", vm_name, c)
                } else {
                    "".to_string()
                }
            } else {
                "".to_string()
            };
            let final_vhd_path = if let Some(ref path) = vhd_path {
                path.clone()
            } else {
                format!("{}\\{}.vhdx", config.default_vhd_directory, vm_name)
            };
            let disk_create_cmd = format!(
                "New-VHD -Path \"{}\" -SizeBytes {} -Dynamic",
                final_vhd_path, vhd_size_bytes
            );
            let disk_attach_cmd = format!(
                "Add-VMHardDiskDrive -VMName \"{}\" -Path \"{}\"",
                vm_name, final_vhd_path
            );
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
            "Set-VMProcessor -VMName \"{}\" -Count {}",
            vm_name, cpu_count
        )),
        HyperVCommand::SetStaticMac {
            vm_name,
            mac_address,
        } => run_powershell(&format!(
            "Set-VMNetworkAdapter -VMName \"{}\" -StaticMacAddress {}",
            vm_name, mac_address
        )),
        HyperVCommand::EnableDynamicMemory { vm_name } => run_powershell(&format!(
            "Set-VMMemory -VMName \"{}\" -DynamicMemoryEnabled $true",
            vm_name
        )),
        HyperVCommand::DisableDynamicMemory { vm_name } => run_powershell(&format!(
            "Set-VMMemory -VMName \"{}\" -DynamicMemoryEnabled $false",
            vm_name
        )),
        HyperVCommand::CreateVhd {
            file_path,
            size_bytes,
        } => run_powershell(&format!(
            "New-VHD -Path \"{}\" -SizeBytes {} -Dynamic",
            file_path, size_bytes
        )),
        HyperVCommand::AttachVhd {
            vm_name,
            file_path,
        } => run_powershell(&format!(
            "Add-VMHardDiskDrive -VMName \"{}\" -Path \"{}\"",
            vm_name, file_path
        )),
        HyperVCommand::DetachVhd {
            vm_name,
            controller_type,
            controller_number,
            controller_location,
        } => run_powershell(&format!(
            "Remove-VMHardDiskDrive -VMName \"{}\" -ControllerType {} -ControllerNumber {} -ControllerLocation {}",
            vm_name, controller_type, controller_number, controller_location
        )),
        HyperVCommand::AttachIso { vm_name, iso_path } => run_powershell(&format!(
            "Add-VMDvdDrive -VMName \"{}\" -Path \"{}\"",
            vm_name, iso_path
        )),
        HyperVCommand::StartVm { vm_name } => {
            run_powershell(&format!("Start-VM -Name \"{}\"", vm_name))
        }
        HyperVCommand::StopVm { vm_name } => {
            run_powershell(&format!("Stop-VM -Name \"{}\" -TurnOff", vm_name))
        }
        HyperVCommand::RebootVm { vm_name } => {
            run_powershell(&format!("Restart-VM -Name \"{}\"", vm_name))
        }
        HyperVCommand::DeleteVm { vm_name } => {
            run_powershell(&format!("Remove-VM -Name \"{}\" -Force", vm_name))
        }
        HyperVCommand::SetStartupMemory {
            vm_name,
            memory_bytes,
        } => run_powershell(&format!(
            "Set-VMMemory -VMName \"{}\" -StartupBytes {}",
            vm_name, memory_bytes
        )),
        HyperVCommand::CreateCheckpoint {
            vm_name,
            checkpoint_name,
        } => run_powershell(&format!(
            "Checkpoint-VM -Name \"{}\" -SnapshotName \"{}\"",
            vm_name, checkpoint_name
        )),
        HyperVCommand::RevertCheckpoint {
            vm_name,
            checkpoint_name,
        } => run_powershell(&format!(
            "Restore-VMCheckpoint -VMName \"{}\" -Name \"{}\"",
            vm_name, checkpoint_name
        )),
        HyperVCommand::RemoveCheckpoint {
            vm_name,
            checkpoint_name,
        } => run_powershell(&format!(
            "Remove-VMCheckpoint -VMName \"{}\" -Name \"{}\" -Confirm:$false",
            vm_name, checkpoint_name
        )),
        HyperVCommand::ListCheckpoints { vm_name } => {
            run_powershell(&format!("Get-VMCheckpoint -VMName \"{}\"", vm_name))
        }
        HyperVCommand::GetVmInfo { vm_name } => {
            run_powershell(&format!("Get-VM -Name \"{}\"", vm_name))
        }
        HyperVCommand::GetVmMemory { vm_name } => {
            run_powershell(&format!("Get-VMMemory -VMName \"{}\"", vm_name))
        }
        HyperVCommand::RenameVm {
            old_vm_name,
            new_vm_name,
        } => run_powershell(&format!(
            "Rename-VM -VMName \"{}\" -NewName \"{}\"",
            old_vm_name, new_vm_name
        )),
        HyperVCommand::ExportVm {
            vm_name,
            export_path,
        } => run_powershell(&format!("Export-VM -Name \"{}\" -Path \"{}\"", vm_name, export_path)),
        HyperVCommand::TestCommand { message } => {
            run_powershell(&format!("Write-Output 'Test command says: {}'", message))
        }
    };

    match ps_result {
        Ok(output) => {
            let msg = format!("success:\n{}", output);
            log_message(&msg);
            HttpResponse::Ok().body(output)
        }
        Err(e) => {
            let msg = format!("error: {}", e);
            log_message(&msg);
            HttpResponse::InternalServerError().body(e)
        }
    }
}

#[get("/vmstatus")]
async fn get_vmstatus() -> impl Responder {
    log_message("get /vmstatus called.");

    let script = r#"
        $vms = Get-VM | Select-Object Name,State,CPUUsage,MemoryAssigned,Id
        if ($vms) {
            if ($vms -isnot [array]) { $vms = @($vms) }
            $vms = $vms | ForEach-Object {
                $_.Id = $_.Id.Guid.ToString()
                $_
            }
            $jsonOutput = $vms | ConvertTo-Json -Depth 3 -Compress
            Write-Output "[$jsonOutput]"
        } else {
            Write-Output "[]"
        }
    "#;

    match run_powershell(script) {
        Ok(raw_output) => {
            let trimmed = raw_output.trim();
            if trimmed == "No VMs found." {
                HttpResponse::Ok().body(trimmed.to_string())
            } else {
                match serde_json::from_str::<serde_json::Value>(trimmed) {
                    Ok(json_val) => HttpResponse::Ok().json(json_val),
                    Err(e) => {
                        let msg = format!(
                            "Could not parse VM data as JSON.\nRaw output:\n{}\nError:\n{}",
                            raw_output, e
                        );
                        log_message(&msg);
                        HttpResponse::InternalServerError().body(msg)
                    }
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

#[get("/vminfo")]
async fn vminfo() -> impl Responder {
    log_message("get /vminfo called.");

    let script = r#"
        $vms = Get-VM
        if ($vms) {
            if ($vms -isnot [array]) { $vms = @($vms) }
            $jsonOutput = $vms | ConvertTo-Json -Depth 5 -Compress
            Write-Output $jsonOutput
        } else {
            Write-Output "[]"
        }
    "#;

    match run_powershell(script) {
        Ok(raw_output) => {
            let trimmed = raw_output.trim();
            match serde_json::from_str::<serde_json::Value>(trimmed) {
                Ok(json_val) => HttpResponse::Ok().json(json_val),
                Err(e) => {
                    let msg = format!(
                        "Could not parse VM info data as JSON.\nRaw output:\n{}\nError:\n{}",
                        raw_output, e
                    );
                    log_message(&msg);
                    HttpResponse::InternalServerError().body(msg)
                }
            }
        }
        Err(e) => {
            let msg = format!("Error retrieving VM info: {}", e);
            log_message(&msg);
            HttpResponse::InternalServerError().body(msg)
        }
    }
}

#[get("/listisos")]
async fn list_isos(data: web::Data<crate::config::AgentConfig>) -> impl Responder {
    log_message("GET /listisos called.");
    let config = data.as_ref();
    let path = Path::new(&config.iso_directory);

    if !path.exists() {
        let msg = format!("ISO directory '{}' does not exist.", &config.iso_directory);
        log_message(&msg);
        return HttpResponse::BadRequest().body(msg);
    }

    let mut iso_files = Vec::new();
    match fs::read_dir(path) {
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

/// Configure all routes for the application.
pub fn init_routes(cfg: &mut web::ServiceConfig) {
    cfg.service(execute_command);
    cfg.service(get_vmstatus);
    cfg.service(vminfo);
    cfg.service(list_isos);
}
