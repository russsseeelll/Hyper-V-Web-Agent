use regex::Regex;
use std::path::Path;
use crate::commands::HyperVCommand;

pub fn validate_vm_name(name: &str) -> Result<(), String> {
    let name = name.trim();
    // Updated regex to allow spaces in addition to alphanumeric characters, underscores, and hyphens.
    let re = Regex::new(r"^[A-Za-z0-9 _-]{1,64}$").unwrap();
    if re.is_match(name) {
        Ok(())
    } else {
        Err(format!(
            "Invalid VM name: '{}'. Only alphanumeric characters, spaces, underscores, and hyphens are allowed (1-64 characters).",
            name
        ))
    }
}

pub fn validate_mac_address(mac: &str) -> Result<(), String> {
    let re = Regex::new(r"^[0-9A-Fa-f]{2}(-[0-9A-Fa-f]{2}){5}$").unwrap();
    if re.is_match(mac) {
        Ok(())
    } else {
        Err(format!("invalid mac address: {}", mac))
    }
}

pub fn validate_checkpoint_name(name: &str) -> Result<(), String> {
    let re = Regex::new(r"^[A-Za-z0-9_\-]{1,64}$").unwrap();
    if re.is_match(name) {
        Ok(())
    } else {
        Err(format!("invalid checkpoint name: {}", name))
    }
}

pub fn validate_file_path(path: &str) -> Result<(), String> {
    if path.contains('|') || path.is_empty() {
        return Err(format!("Invalid file path: '{}'. Path cannot contain '|' and cannot be empty.", path));
    }
    let p = Path::new(path);
    if !p.is_absolute() {
        return Err(format!("File path must be absolute: '{}'.", path));
    }
    Ok(())
}

pub fn validate_generation(gen: u8) -> Result<(), String> {
    match gen {
        1 | 2 => Ok(()),
        _ => Err(format!("invalid vm generation: {}", gen)),
    }
}

pub fn validate_cpu_count(count: u32) -> Result<(), String> {
    if count == 0 || count > 64 {
        return Err(format!("cpu count out of range: {}", count));
    }
    Ok(())
}

pub fn validate_memory_bytes(bytes: u64) -> Result<(), String> {
    if bytes < 512_000_000 {
        return Err(format!(
            "memory bytes too low (min ~512mb recommended): {}",
            bytes
        ));
    }
    if bytes > 1_000_000_000_000 {
        return Err(format!(
            "memory bytes too large (>1tb not allowed in this example): {}",
            bytes
        ));
    }
    Ok(())
}

pub fn validate_command(cmd: &HyperVCommand) -> Result<(), String> {
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
                return Err(format!("invalid controller type: {}", controller_type));
            }
            if *controller_number > 3 {
                return Err(format!("invalid controller number: {}", controller_number));
            }
            if *controller_location > 64 {
                return Err(format!("invalid controller location: {}", controller_location));
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
                return Err("test message cannot be empty".to_string());
            }
            Ok(())
        }
    }
}
