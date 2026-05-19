use evdev::{Device, InputEventKind, Key};
use std::io::{self, Write};
use std::thread;
use std::time::Duration;
use sysinfo::{ProcessesToUpdate, System};

struct MonitorArgs {
    process_name: String,
}

fn main() {
    println!("=== Anti-Cheat System v5.0 (Hybrid) ===");
    
    let mut stdin = io::stdin();
    let mut stdout = io::stdout();
    let mut input = String::new();

    stdout.write_all(b"Ingresa el nombre del proceso a vigilar (ej: firefox): ").unwrap();
    stdout.flush().unwrap();
    stdin.read_line(&mut input).unwrap();
    let process_name = input.trim().to_string();

    input.clear();
    stdout.write_all(b"Ingresa la ruta del dispositivo del raton (ej: /dev/input/event7): ").unwrap();
    stdout.flush().unwrap();
    stdin.read_line(&mut input).unwrap();
    let device_path = input.trim().to_string();

    println!("\nIniciando monitoreo... (Presiona Ctrl+C para salir)");

    let device_path_clone = device_path.clone();
    let process_name_clone = process_name.clone();

    // Hilo 2: Guardián de Hardware
    let hardware_guardian = thread::spawn(move || {
        run_evdev_guardian(device_path_clone);
    });

    // Hilo 1: Monitor de RAM
    let monitor_args = MonitorArgs {
        process_name: process_name_clone,
    };
    let memory_monitor = thread::spawn(move || {
        run_memory_monitor(monitor_args);
    });

    println!("Hilos iniciados. Esperando interrupción...");
    
    let _ = hardware_guardian.join();
    let _ = memory_monitor.join();
}

fn run_evdev_guardian(device_path: String) {
    println!("[Hilo Hardware] Abriendo dispositivo: {}", device_path);
    
    let mut device = match Device::open(&device_path) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("[Hilo Hardware] ERROR al abrir {}: {}", device_path, e);
            return;
        }
    };

    println!("[Hilo Hardware] Dispositivo abierto. Escuchando eventos...");

    loop {
        match device.fetch_events() {
            Ok(events) => {
                for event in events {
                    if let InputEventKind::Key(key) = event.kind() {
                        // Detectamos clics físicos con valor 1 (pressed)
                        if (key == Key::BTN_LEFT || key == Key::BTN_RIGHT) && event.value() == 1 {
                            println!("[ALERTA HARDWARE] Clic físico detectado en {}: {:?}", device_path, key);
                        }
                    }
                }
            },
            Err(e) => {
                eprintln!("[Hilo Hardware] ERROR al leer eventos del dispositivo: {}", e);
                // Parche de seguridad para evitar uso de CPU al 100% en caso de error continuo
                thread::sleep(Duration::from_millis(100));
            }
        }
    }
}

fn run_memory_monitor(args: MonitorArgs) {
    println!("[Hilo RAM] Buscando proceso: '{}'", args.process_name);

    let mut sys = System::new_all();
    // sysinfo 0.39.1 syntax requires explicit update arguments
    sys.refresh_processes(ProcessesToUpdate::All, true);

    // .processes_by_name now returns &Process, we extract the PID with .pid()
    let target_pid = sys.processes_by_name(args.process_name.as_ref())
        .next()
        .map(|process| process.pid());

    if target_pid.is_none() {
        eprintln!("[Hilo RAM] ERROR: El proceso '{}' no fue encontrado.", args.process_name);
        return;
    }

    let pid = target_pid.unwrap();
    println!("[Hilo RAM] Monitorizando PID: {}", pid.as_u32());

    let mut previous_memory = 0.0;
    let sleep_time = Duration::from_secs(1);

    loop {
        // Only refresh our target process to save CPU cycles
        sys.refresh_processes(ProcessesToUpdate::Some(&[pid]), false);
        
        let current_memory_mb = sys.process(pid)
            .map(|p| p.memory() as f64 / 1024.0 / 1024.0)
            .unwrap_or(0.0);

        if previous_memory > 0.0 {
            let delta = current_memory_mb - previous_memory;
            
            if delta > 15.0 {
                // AQUÍ ESTÁ LA NUEVA LÓGICA DE CASTIGO
                println!("[ALERTA RAM] Pico Anómalo en PID {}: +{:.2} MB en 1s", pid.as_u32(), delta);
                println!("[BANNED] Ejecutando orden SIGKILL. Cerrando proceso...");

                if let Some(process) = sys.process(pid) {
                    process.kill(); 
                }

                break; 
            }
        }

        previous_memory = current_memory_mb;
        thread::sleep(sleep_time);
    }
}