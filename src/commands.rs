// this enum defines all supported hyper-v commands

use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub enum HyperVCommand {
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

// the command request struct wraps a hyper-v command for processing in api endpoints
#[derive(Debug, Deserialize)]
pub struct CommandRequest {
    pub command: HyperVCommand,
}