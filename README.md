# Linux System Telemetry: Hybrid Anti-Cheat Engine v5.0

An advanced, low-level hybrid anti-cheat prototype implemented in Rust for Linux environments. This engine employs a multi-threaded architecture to concurrently monitor raw hardware input events and real-time process memory telemetry, enforcing system integrity via kernel-level execution.

## 🚀 Architecture Overview

The engine spawns two independent, decoupled execution threads supervised by the main process coordinator to ensure zero-latency detection without blocking system resources:

1. **Hardware Guardian (`evdev` Stream Monitor):** Intercepts raw event streams directly from the Linux input subsystem (`/dev/input/event*`). By tracking physical state transitions (e.g., `BTN_LEFT`, `BTN_RIGHT`), it guarantees that mouse inputs originate from an authentic physical hardware interface, isolating user-space software macros or automated aimbots.

2. **Memory Monitor (`sysinfo` RSS Auditor):**
   Tracks the Resident Set Size (RSS) of a specified target process ID (PID). It computes memory consumption deltas on a strict 1-second window. Anomalous volumetric expansions (>15MB/s) trigger immediate automated enforcement to neutralize memory-injection vectors (such as unauthorized dynamic library injections).

## 🛡️ Enforcement & Resilience

* **Kernel-Level Termination:** Upon anomaly validation, the engine bypasses user-space resistance by issuing a non-catchable `SIGKILL` directive through the OS subsystem, terminating the target process instantly.
* **Resource-Guard Pauses:** Includes structured micro-sleep intervals (`100ms`) within failure-state loops to prevent CPU starvation (0% thread locking) in the event of hardware device disconnection.
* **Panic-Free Error Handling:** Implements idiomatic Rust pattern matching (`match` and `if let Some`) instead of blind unwrap operations, ensuring continuous uptime under adversarial environments.

## 📋 Prerequisites

- **Operating System:** Linux (Kernel 5.x or higher with active `evdev` subsystem support). Tested on Pop!_OS.
- **Language Runtime:** Rustc & Cargo (Edition 2021).
- **Privileges:** Administrative access (`sudo`) is strictly required to poll raw `/dev/input/` character devices and audit restricted process memory spaces.

## ⚙️ Compilation & Execution

1. Clone the repository and navigate to the root directory:
```bash
git clone [https://github.com/diegodevxd/linux-system-telemetry.git](https://github.com/diegodevxd/linux-system-telemetry.git)
cd linux-system-telemetry
```

2. Build the optimized production binary:
```bash
cargo build --release
```

3. Execute the binary with administrative privileges:
```bash
sudo ./target/release/observador
```
*(Note: If your compiled binary has a different name specified in Cargo.toml, replace `observador` with your binary name, or simply use `sudo cargo run`)*.

4. Provide the system parameters when prompted:
   - **Target Process:** e.g., `firefox`
   - **Input Device Path:** e.g., `/dev/input/event7` *(Verify your mouse event path via `cat /proc/bus/input/devices` if needed)*.

## 🛠️ Tech Stack & Dependencies

- **Rust** (Systems-level memory safety, concurrency without data races).
- **`evdev` crate** (Pure Rust interface for Linux evdev devices).
- **`sysinfo` crate** (Low-overhead system and process telemetry).

## ⚖️ License

Distributed under the MIT License. See `LICENSE` for more information.
