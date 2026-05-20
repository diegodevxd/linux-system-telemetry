use evdev::{Device, InputEventKind, Key};
use std::fs::{File, OpenOptions};
use std::io::{self, BufRead, BufReader, Read, Seek, SeekFrom, Write};
use std::thread;
use std::time::Duration;
use sysinfo::{ProcessesToUpdate, System};
use chrono::Local; // Importamos la librería de tiempo

struct MonitorArgs {
    process_name: String,
}

const CHEAT_SIGNATURE: &[u8] = &[0x48, 0x89, 0xE5, 0x5D, 0xC3];

// === NUEVO: MÓDULO DE LOGS ===
// Esta función abre el archivo en modo "Append" (añadir al final) y escribe la evidencia.
fn registrar_log(accion: &str, pid: u32, detalle: &str) {
    // Obtenemos la hora local exacta
    let fecha_hora = Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
    
    // Armamos el mensaje final
    let mensaje = format!("[{}] ACCIÓN: {} | PID: {} | DETALLE: {}\n", fecha_hora, accion, pid, detalle);

    // Abrimos el archivo guardando el historial anterior
    if let Ok(mut file) = OpenOptions::new().create(true).append(true).open("/home/capibtcdev/observador/anticheat.log") {
        let _ = file.write_all(mensaje.as_bytes());
    }
}

fn main() {
    println!("=== Anti-Cheat System v5.0 (Hybrid MVP Completo) ===");
    
    let stdin = io::stdin();
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

    let hardware_guardian = thread::spawn(move || {
        run_evdev_guardian(device_path_clone);
    });

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

fn verificar_librerias_inyectadas(pid: u32) -> bool {
    let maps_path = format!("/proc/{}/maps", pid);
    let file = match File::open(&maps_path) {
        Ok(f) => f,
        Err(_) => return false, 
    };

    let reader = BufReader::new(file);
    let rutas_sospechosas = vec!["/tmp/", "/dev/shm/", ".cheat", ".local/share/tricks"];

    for line_result in reader.lines() {
        if let Ok(line) = line_result {
            if line.contains(".so") {
                for ruta in &rutas_sospechosas {
                    if line.contains(ruta) {
                        println!("[ALERTA CRÍTICA] Librería .so maliciosa inyectada desde: {}", line.trim());
                        return true; 
                    }
                }
            }
        }
    }
    false 
}

fn escanear_firmas_en_memoria(pid: u32) -> bool {
    let maps_path = format!("/proc/{}/maps", pid);
    let mem_path = format!("/proc/{}/mem", pid);

    let maps_file = match File::open(&maps_path) {
        Ok(f) => f,
        Err(_) => return false,
    };
    
    let mut mem_file = match File::open(&mem_path) {
        Ok(f) => f,
        Err(_) => return false,
    };

    let reader = BufReader::new(maps_file);

    for line_result in reader.lines() {
        if let Ok(line) = line_result {
            if line.contains(" r") {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.is_empty() { continue; }
                
                let range: Vec<&str> = parts[0].split('-').collect();
                if range.len() != 2 { continue; }

                let start_addr = u64::from_str_radix(range[0], 16).unwrap_or(0);
                let end_addr = u64::from_str_radix(range[1], 16).unwrap_or(0);
                let size = (end_addr - start_addr) as usize;

                if size > 0 && size < 10_485_760 {
                    if mem_file.seek(SeekFrom::Start(start_addr)).is_ok() {
                        let mut buffer = vec![0; size];
                        if mem_file.read_exact(&mut buffer).is_ok() {
                            if buscar_secuencia(&buffer, CHEAT_SIGNATURE) {
                                println!("[ALERTA CRÍTICA] Firma maliciosa (ADN) detectada en memoria (0x{:x})", start_addr);
                                return true; 
                            }
                        }
                    }
                }
            }
        }
    }
    false 
}

fn buscar_secuencia(buffer: &[u8], secuencia: &[u8]) -> bool {
    if secuencia.is_empty() || buffer.len() < secuencia.len() {
        return false;
    }
    buffer.windows(secuencia.len()).any(|window| window == secuencia)
}

fn run_evdev_guardian(device_path: String) {
    let mut device = match Device::open(&device_path) {
        Ok(d) => d,
        Err(_) => return,
    };

    loop {
        match device.fetch_events() {
            Ok(events) => {
                for event in events {
                    if let InputEventKind::Key(key) = event.kind() {
                        if (key == Key::BTN_LEFT || key == Key::BTN_RIGHT) && event.value() == 1 {
                            // En producción los clics de ratón no se logean para no llenar el disco duro, solo se imprimen.
                            println!("[ALERTA HARDWARE] Clic físico detectado: {:?}", key);
                        }
                    }
                }
            },
            Err(_) => {
                thread::sleep(Duration::from_millis(100));
            }
        }
    }
}

fn run_memory_monitor(args: MonitorArgs) {
    let mut sys = System::new_all();
    sys.refresh_processes(ProcessesToUpdate::All, true);

    let target_pid = sys.processes_by_name(args.process_name.as_ref())
        .next()
        .map(|process| process.pid());

    if target_pid.is_none() {
        eprintln!("[Hilo RAM] ERROR: Proceso '{}' no encontrado.", args.process_name);
        return;
    }

    let pid = target_pid.unwrap();
    println!("[Hilo RAM] Monitorizando PID objetivo: {}", pid.as_u32());

    let lista_negra = vec!["gdb", "scanmem", "gameconqueror", "artmoney", "cheatengine"];
    let mut previous_memory = 0.0;
    let mut contador_escaneo_global = 0;

    loop {
        sys.refresh_processes(ProcessesToUpdate::Some(&[pid]), false);
        let current_memory_mb = sys.process(pid).map(|p| p.memory() as f64 / 1024.0 / 1024.0).unwrap_or(0.0);

        if previous_memory > 0.0 {
            let delta = current_memory_mb - previous_memory;
            if delta > 15.0 {
                println!("[ALERTA RAM] Pico Anómalo: +{:.2} MB", delta);
                println!("[BANNED] Ejecutando SIGKILL...");
                registrar_log("BANNED", pid.as_u32(), &format!("Pico de RAM anomalo: +{:.2} MB", delta)); // <-- GUARDAMOS LOG
                if let Some(process) = sys.process(pid) { process.kill(); }
                break; 
            }
        }
        previous_memory = current_memory_mb;

        contador_escaneo_global += 1;
        if contador_escaneo_global >= 3 {
            
            if verificar_librerias_inyectadas(pid.as_u32()) {
                println!("[BANNED] Inyección detectada. Cerrando proceso...");
                registrar_log("BANNED", pid.as_u32(), "Librería .so maliciosa inyectada detectada."); // <-- GUARDAMOS LOG
                if let Some(target_proc) = sys.process(pid) { target_proc.kill(); }
                return; 
            }

            if escanear_firmas_en_memoria(pid.as_u32()) {
                println!("[BANNED] Firma de memoria detectada. Cerrando proceso...");
                registrar_log("BANNED", pid.as_u32(), "Firma maliciosa (ADN) detectada en memoria RAM."); // <-- GUARDAMOS LOG
                if let Some(target_proc) = sys.process(pid) { target_proc.kill(); }
                return; 
            }

            sys.refresh_processes(ProcessesToUpdate::All, false);
            for (sys_pid, process) in sys.processes() {
                let name = process.name().to_string_lossy().to_lowercase();
                if lista_negra.iter().any(|&bad_proc| name == bad_proc || name.starts_with(&(bad_proc.to_string() + " "))) {
                    println!("[ALERTA ENTORNO] Proceso prohibido: '{}' (PID: {})", name, sys_pid.as_u32());
                    println!("[BANNED] Seguridad comprometida...");
                    registrar_log("BANNED", pid.as_u32(), &format!("Proceso prohibido ejecutándose en segundo plano: {}", name)); // <-- GUARDAMOS LOG
                    if let Some(target_proc) = sys.process(pid) { target_proc.kill(); }
                    return;
                }
            }
            contador_escaneo_global = 0;
        }
        thread::sleep(Duration::from_secs(1));
    }
}