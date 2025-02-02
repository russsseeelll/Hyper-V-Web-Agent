// this file defines the endpoints for the hyper-v web agent.
// endpoints include executing commands, retrieving vm status/info and listing iso files.

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
// receives a json payload with a hyper-v command, validates it, runs the corresponding powershell script,
// and returns the output or an error message.
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
                "new-vm -name \"{}\" -memorystartupbytes {} -generation {}",
                vm_name, memory_bytes, generation
            );
            let connect_cmd = if config.ethernet_switch.to_lowercase() != "none" {
                format!(
                    "connect-vmnetworkadapter -vmname \"{}\" -switchname '{}'",
                    vm_name, config.ethernet_switch
                )
            } else {
                "".to_string()
            };
            let cpu_cmd = if let Some(c) = cpu_count {
                if *c > 1 {
                    format!("set-vmprocessor -vmname \"{}\" -count {}", vm_name, c)
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
                "new-vhd -path \"{}\" -sizebytes {} -dynamic",
                final_vhd_path, vhd_size_bytes
            );
            let disk_attach_cmd = format!(
                "add-vmharddiskdrive -vmname \"{}\" -path \"{}\"",
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
            "set-vmprocessor -vmname \"{}\" -count { }",
            vm_name, cpu_count
        )),
        HyperVCommand::SetStaticMac {
            vm_name,
            mac_address,
        } => run_powershell(&format!(
            "set-vmnetworkadapter -vmname \"{}\" -staticmacaddress {}",
            vm_name, mac_address
        )),
        HyperVCommand::EnableDynamicMemory { vm_name } => run_powershell(&format!(
            "set-vmmemory -vmname \"{}\" -dynamicmemoryenabled $true",
            vm_name
        )),
        HyperVCommand::DisableDynamicMemory { vm_name } => run_powershell(&format!(
            "set-vmmemory -vmname \"{}\" -dynamicmemoryenabled $false",
            vm_name
        )),
        HyperVCommand::CreateVhd {
            file_path,
            size_bytes,
        } => run_powershell(&format!(
            "new-vhd -path \"{}\" -sizebytes {} -dynamic",
            file_path, size_bytes
        )),
        HyperVCommand::AttachVhd {
            vm_name,
            file_path,
        } => run_powershell(&format!(
            "add-vmharddiskdrive -vmname \"{}\" -path \"{}\"",
            vm_name, file_path
        )),
        HyperVCommand::DetachVhd {
            vm_name,
            controller_type,
            controller_number,
            controller_location,
        } => run_powershell(&format!(
            "remove-vmharddiskdrive -vmname \"{}\" -controllertype {} -controllernumber {} -controllerlocation {}",
            vm_name, controller_type, controller_number, controller_location
        )),
        HyperVCommand::AttachIso { vm_name, iso_path } => {
            let iso_path_obj = Path::new(iso_path);
            let final_iso_path = if iso_path_obj.is_absolute() {
                iso_path.to_string()
            } else {
                format!("{}\\{}", config.iso_directory, iso_path)
            };
            run_powershell(&format!(
                "add-vmdvddrive -vmname \"{}\" -path \"{}\"",
                vm_name, final_iso_path
            ))
        }
        HyperVCommand::StartVm { vm_name } => {
            run_powershell(&format!("start-vm -name \"{}\"", vm_name))
        }
        HyperVCommand::StopVm { vm_name } => {
            run_powershell(&format!("stop-vm -name \"{}\" -turnoff", vm_name))
        }
        HyperVCommand::RebootVm { vm_name } => {
            run_powershell(&format!("restart-vm -name \"{}\"", vm_name))
        }
        HyperVCommand::DeleteVm { vm_name } => {
            run_powershell(&format!("remove-vm -name \"{}\" -force", vm_name))
        }
        HyperVCommand::SetStartupMemory {
            vm_name,
            memory_bytes,
        } => run_powershell(&format!(
            "set-vmmemory -vmname \"{}\" -startupbytes {}",
            vm_name, memory_bytes
        )),
        HyperVCommand::CreateCheckpoint {
            vm_name,
            checkpoint_name,
        } => run_powershell(&format!(
            "checkpoint-vm -name \"{}\" -snapshotname \"{}\"",
            vm_name, checkpoint_name
        )),
        HyperVCommand::RevertCheckpoint { vm_name, checkpoint_name } => {
            run_powershell(&format!(
                "restore-vmcheckpoint -vmname \"{}\" -name \"{}\" -confirm:$false",
                vm_name, checkpoint_name
            ))
        }
        HyperVCommand::RemoveCheckpoint {
            vm_name,
            checkpoint_name,
        } => run_powershell(&format!(
            "remove-vmcheckpoint -vmname \"{}\" -name \"{}\" -confirm:$false",
            vm_name, checkpoint_name
        )),
        HyperVCommand::ListCheckpoints { vm_name } => {
            let script = format!("
        $checkpoints = get-vmcheckpoint -vmname \"{}\";
        if ($checkpoints -is [array]) {{
            $checkpoints | select-object name, creationtime | convertto-json -compress
        }} else {{
            @($checkpoints | select-object name, creationtime) | convertto-json -compress
        }}
    ", vm_name);
            run_powershell(&script)
        }
        HyperVCommand::GetVmInfo { vm_name } => {
            run_powershell(&format!("get-vm -name \"{}\"", vm_name))
        }
        HyperVCommand::GetVmMemory { vm_name } => {
            run_powershell(&format!("get-vmmemory -vmname \"{}\"", vm_name))
        }
        HyperVCommand::RenameVm {
            old_vm_name,
            new_vm_name,
        } => run_powershell(&format!(
            "rename-vm -vmname \"{}\" -newname \"{}\"",
            old_vm_name, new_vm_name
        )),
        HyperVCommand::ExportVm {
            vm_name,
            export_path,
        } => run_powershell(&format!("export-vm -name \"{}\" -path \"{}\"", vm_name, export_path)),
        HyperVCommand::TestCommand { message } => {
            run_powershell(&format!("write-output 'test command says: {}'", message))
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
// retrieves the status of vms by running a powershell script and returns the output as json.
async fn get_vmstatus() -> impl Responder {
    log_message("get /vmstatus called.");

    let script = r#"
        $vms = get-vm | select-object name,state,cpuusage,memoryassigned,id
        if ($vms) {
            if ($vms -isnot [array]) { $vms = @($vms) }
            $vms = $vms | foreach-object {
                $_.id = $_.id.guid.tostring()
                $_
            }
            $jsonoutput = $vms | convertto-json -depth 3 -compress
            write-output "[$jsonoutput]"
        } else {
            write-output "[]"
        }
    "#;

    match run_powershell(script) {
        Ok(raw_output) => {
            let trimmed = raw_output.trim();
            if trimmed == "no vms found." {
                HttpResponse::Ok().body(trimmed.to_string())
            } else {
                match serde_json::from_str::<serde_json::Value>(trimmed) {
                    Ok(json_val) => HttpResponse::Ok().json(json_val),
                    Err(e) => {
                        let msg = format!(
                            "could not parse vm data as json.\nraw output:\n{}\nerror:\n{}",
                            raw_output, e
                        );
                        log_message(&msg);
                        HttpResponse::InternalServerError().body(msg)
                    }
                }
            }
        }
        Err(e) => {
            let msg = format!("error retrieving vm status: {}", e);
            log_message(&msg);
            HttpResponse::InternalServerError().body(msg)
        }
    }
}

#[get("/vminfo")]
// retrieves detailed info about the vms by running a powershell script and returns the output as json.
async fn vminfo() -> impl Responder {
    log_message("get /vminfo called.");

    let script = r#"
        $vms = get-vm
        if ($vms) {
            if ($vms -isnot [array]) { $vms = @($vms) }
            $jsonoutput = $vms | convertto-json -depth 5 -compress
            write-output $jsonoutput
        } else {
            write-output "[]"
        }
    "#;

    match run_powershell(script) {
        Ok(raw_output) => {
            let trimmed = raw_output.trim();
            match serde_json::from_str::<serde_json::Value>(trimmed) {
                Ok(json_val) => HttpResponse::Ok().json(json_val),
                Err(e) => {
                    let msg = format!(
                        "could not parse vm info data as json.\nraw output:\n{}\nerror:\n{}",
                        raw_output, e
                    );
                    log_message(&msg);
                    HttpResponse::InternalServerError().body(msg)
                }
            }
        }
        Err(e) => {
            let msg = format!("error retrieving vm info: {}", e);
            log_message(&msg);
            HttpResponse::InternalServerError().body(msg)
        }
    }
}

#[get("/listisos")]
// reads the configured iso directory and returns a json array of iso filenames.
async fn list_isos(data: web::Data<crate::config::AgentConfig>) -> impl Responder {
    log_message("get /listisos called.");
    let config = data.as_ref();
    let path = std::path::Path::new(&config.iso_directory);

    if !path.exists() {
        let msg = format!("iso directory '{}' does not exist.", &config.iso_directory);
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
            let msg = format!("error reading iso directory: {}", e);
            log_message(&msg);
            HttpResponse::InternalServerError().body(msg)
        }
    }
}

// registers all the endpoints for the application.
pub fn init_routes(cfg: &mut web::ServiceConfig) {
    cfg.service(execute_command);
    cfg.service(get_vmstatus);
    cfg.service(vminfo);
    cfg.service(list_isos);
}