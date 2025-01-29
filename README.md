# Hyper-V Web Agent

A Rust-based connector to remotely manage Microsoft Hyper-V servers. This agent exposes a simple HTTP API over port `7623` (by default) that allows you to:

- Create, start, stop, reboot, rename, and delete VMs.
- Manage virtual disks (create, attach, detach).
- Attach ISO images from a specified directory.
- Retrieve VM status (CPU usage, memory assignment, etc.).
- Manage VM checkpoints (create, revert, remove).
- Export VMs to a specified folder.

## How It Works

1. **Run as Administrator**: This agent requires administrative privileges to manage Hyper-V. If the agent detects it’s not running as admin, it will prompt you to relaunch with admin privileges.

2. **Configuration**:
    - On first run, the agent prompts you to select a Hyper-V switch from a text-based menu (or choose “none”) and specify two directories:
        - **ISO directory** for storing `.iso` files.
        - **VHDX directory** for creating new virtual disks by default.
    - It then writes a JSON file named `hyperv_agent_config.json` to the same folder as the agent executable, storing these preferences.

3. **Endpoints**: The agent listens on port `7623` by default, exposing three endpoints:
    - `POST /execute` – Accepts JSON commands to perform Hyper-V operations.
    - `GET /vmstatus` – Returns JSON describing all local VMs.
    - `GET /listisos` – Returns the `.iso` filenames in the configured ISO directory.

4. **Implementation**: Written in Rust, with Actix Web for HTTP server handling and calls to `powershell.exe -Command <script>` for each Hyper-V operation.

## Basic Usage

1. **Open a console** with Administrator privileges.
2. **Run** the agent executable:

`hyperv_agent.exe`

3. **Answer** the prompts on first run (choose your virtual switch, ISO directory, and VHDX directory).
4. The agent then listens on `0.0.0.0:7623` (or a configured IP:port if you changed it).
5. **Use cURL** or any HTTP client to send JSON requests to `http://<SERVER_URL>:7623`.

Example: Creating a VM named `testvm` with 4 GB of RAM, generation 2, 2 CPU cores, and a new VHDX of 20 GB in the default directory:

```bash
curl -X POST "http://<SERVER_URL>:7623/execute" \
  -H "Content-Type: application/json" \
  -d '{
    "command": {
      "createVm": {
        "vm_name": "testvm",
        "memory_bytes": 4294967296,
        "generation": 2,
        "cpu_count": 2,
        "vhd_size_bytes": 21474836480
      }
    }
  }'
  
```

If vhd_path is omitted, the agent automatically uses the default VHDX directory from hyperv_agent_config.json (e.g., C:\VMs\testvm.vhdx). If you do specify vhd_path, that location takes precedence.


# API Documentation

The Hyper-V Web Agent is a Rust-based connector for managing Hyper-V environments over an HTTP API. By default, it listens on port \`7623\`. You can send requests to \`http://SERVER_URL:7623\`.

---

## **POST** /execute

Send a JSON payload containing a single top-level \`"command"\` object. For example:

```
{
  "command": {
    "createVm": {
      "vm_name": "MyVM",
      "memory_bytes": 2147483648,
      "generation": 2,
      "cpu_count": 2,
      "vhd_size_bytes": 21474836480
    }
  }
}
```

### Command Variants

1. **createVm**
    - `vm_name` (string)
    - `memory_bytes` (u64, in bytes, e.g. `2147483648`)
    - `generation` (1 or 2)
    - `cpu_count` (optional, integer 1-64)
    - `vhd_size_bytes` (u64, always required for a new virtual disk)
    - `vhd_path` (optional, full path to the new disk; if omitted, defaults to `<config.default_vhd_directory>\\<vm_name>.vhdx`)

2. **startVm** / **stopVm** / **rebootVm** / **deleteVm**
    - `vm_name`: (string)

3. **attachIso**
    - `vm_name`: (string)
    - `iso_path`: (string, e.g. \`C:\\ISOs\\WinServer2022.iso\`)

4. **createVhd** / **attachVhd** / **detachVhd**
    - **createVhd**: `file_path`, `size_bytes`
    - **attachVhd**: `vm_name`, `file_path`
    - **detachVhd**: `vm_name`, `controller_type` (`IDE` or `SCSI`), etc.

5. **setVmProcessor**
    - `vm_name`: (string)
    - `cpu_count`: (integer 1-64)

6. **createCheckpoint** / **revertCheckpoint** / **removeCheckpoint** / **listCheckpoints**
    - `vm_name`: (string)
    - **create/revert/remove** also require `checkpoint_name` (string)

7. **renameVm**
    - `old_vm_name`: (string)
    - `new_vm_name`: (string)

8. **exportVm**
    - `vm_name`: (string)
    - `export_path`: (string, directory path)

9. **setStartupMemory**
    - `vm_name`: (string)
    - `memory_bytes`: (u64)

10. **testCommand**
    - `message`: (string) — echoes back for debugging

---

### Example Request

```
curl -X POST "http://<SERVER_URL>:7623/execute" \\
     -H "Content-Type: application/json" \\
     -d '{
       "command": {
         "createVm": {
           "vm_name": "testvm",
           "memory_bytes": 4294967296,
           "generation": 2,
           "cpu_count": 2,
           "vhd_size_bytes": 21474836480
         }
       }
     }'
```

This would create a VM called \`testvm\` with 4GB RAM, Generation 2, 2 CPU cores, and a 20GB disk at `<default_vhd_directory>\testvm.vhdx`.

---

## **GET** /vmstatus

Returns an array describing all local Hyper-V VMs, e.g.:

```
[
  {
    "Name": "testvm",
    "State": 2,
    "CPUUsage": 0,
    "MemoryAssigned": 4294967296
  },
  {
    "Name": "AnotherVM",
    "State": 3,
    "CPUUsage": 10,
    "MemoryAssigned": 2147483648
  }
]
```

---

## **GET** /listisos

Lists all \`.iso\` files in the configured ISO directory. Example response:

```
["Windows2022.iso","UbuntuServer.iso","Recovery.iso"]
```

---

## Security & Permissions

- **Administrator**: Must run as admin or LocalSystem to have full Hyper-V control.
- **Firewall**: Open port \`7623\` inbound if needed.
- **Transport**: No TLS by default. Consider using HTTPS or a reverse proxy for secure transport.

## Building / Cross-Compiling

```
cargo build --release
```

On macOS to target Windows:

```
rustup target add x86_64-pc-windows-gnu
brew install mingw-w64
cargo build --release --target x86_64-pc-windows-gnu
```

The MIT License (MIT)
=====================

Copyright © `2025` `@russsseeelll`

Permission is hereby granted, free of charge, to any person
obtaining a copy of this software and associated documentation
files (the “Software”), to deal in the Software without
restriction, including without limitation the rights to use,
copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the
Software is furnished to do so, subject to the following
conditions:

The above copyright notice and this permission notice shall be
included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
OTHER DEALINGS IN THE SOFTWARE.
