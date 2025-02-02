// this file contains helper functions to validate various inputs for hyper-v commands,
// such as vm names, mac addresses, file paths, memory sizes, etc.

use regex::Regex;
use std::path::Path;
use crate::commands::HyperVCommand;

// checks that the vm name is between 1 and 64 characters and contains only allowed characters.
pub fn validate_vm_name(name: &str) -> Result<(), String> {
    let name = name.trim();
    // updated regex to allow spaces in addition to alphanumeric characters, underscores, and hyphens.
    let re = Regex::new(r"^[A-Za-z0-9 _-]{1,64}$").unwrap();
    if re.is_match(name) {
        Ok(())
    } else {
        Err(format!(
            "invalid vm name: '{}'. only alphanumeric characters, spaces, underscores, and hyphens are allowed (1-64 characters).",
            name
        ))
    }
}

// checks that the mac address is in a valid format (xx-xx-xx-xx-xx-xx).
pub fn validate_mac_address(mac: &str) -> Result<(), String> {
    let re = Regex::new(r"^[0-9A-Fa-f]{2}(-[0-9A-Fa-f]{2}){5}$").unwrap();
    if re.is_match(mac) {
        Ok(())
    } else {
        Err(format!("invalid mac address: {}", mac))
    }
}

// checks that the checkpoint name is between 1 and 64 characters and uses allowed characters.
pub fn validate_checkpoint_name(name: &str) -> Result<(), String> {
    let re = Regex::new(r"^[A-Za-z0-9_\-]{1,64}$").unwrap();
    if re.is_match(name) {
        Ok(())
    } else {
        Err(format!("invalid checkpoint name: {}", name))
    }
}

// validates that the file path is absolute and does not contain forbidden characters.
pub fn validate_file_path(path: &str) -> Result<(), String> {
    if path.contains('|') || path.is_empty() {
        return Err(format!("invalid file path: '{}'. path cannot contain '|' and cannot be empty.", path));
    }
    let p = Path::new(path);
    if !p.is_absolute() {
        return Err(format!("file path must be absolute: '{}'.", path));
    }
    Ok(())
}

// checks that the vm generation is either 1 or 2.
pub fn validate_generation(gen: u8) -> Result<(), String> {
    match gen {
        1 | 2 => Ok(()),
        _ => Err(format!("invalid vm generation: {}", gen)),
    }
}

// checks that the cpu count is within a valid range (1 to 64).
pub fn validate_cpu_count(count: u32) -> Result<(), String> {
    if count == 0 || count > 64 {
        return Err(format!("cpu count out of range: {}", count));
    }
    Ok(())
}

// checks that the memory bytes are above a minimum and below a maximum value.
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

// validates the hyper-v command by calling the appropriate validation function for each command type.
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
            if !["ide", "scsi"].contains(&controller_type.to_lowercase().as_str()) {
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
            let p = Path::new(iso_path);
            if p.is_absolute() {
                validate_file_path(iso_path)?;
            }
            Ok(())
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
