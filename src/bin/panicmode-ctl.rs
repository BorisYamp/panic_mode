/// panicmode-ctl — CLI для управления демоном PanicMode через Unix-сокет.
///
/// Использование:
///   panicmode-ctl list                # список заблокированных IP
///   panicmode-ctl unblock 1.2.3.4    # снять блок вручную
///
/// Путь к сокету: /run/panicmode/ctl.sock
/// Переопределить: PANICMODE_CTL_SOCKET=/другой/путь panicmode-ctl list
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::time::Duration;

use serde::Deserialize;
use serde_json::{json, Value};

const DEFAULT_SOCKET: &str = "/run/panicmode/ctl.sock";

fn main() {
    let args: Vec<String> = std::env::args().collect();

    if args.len() < 2 {
        eprintln!("Использование: panicmode-ctl <команда> [аргументы]");
        eprintln!();
        eprintln!("Команды:");
        eprintln!("  list                  Показать все активные блоки IP");
        eprintln!("  unblock <IP>          Снять блокировку с указанного IP");
        std::process::exit(1);
    }

    let socket_path = std::env::var("PANICMODE_CTL_SOCKET")
        .unwrap_or_else(|_| DEFAULT_SOCKET.to_string());

    let request = match args[1].as_str() {
        "list" => json!({"cmd": "list"}),
        "unblock" => {
            if args.len() < 3 {
                eprintln!("Ошибка: укажите IP-адрес. Пример: panicmode-ctl unblock 1.2.3.4");
                std::process::exit(1);
            }
            json!({"cmd": "unblock", "ip": args[2]})
        }
        cmd => {
            eprintln!("Неизвестная команда: {}", cmd);
            std::process::exit(1);
        }
    };

    match run(&socket_path, &request) {
        Ok(()) => {}
        Err(e) => {
            eprintln!("Ошибка: {}", e);
            std::process::exit(1);
        }
    }
}

fn run(socket_path: &str, request: &Value) -> Result<(), String> {
    let mut stream = UnixStream::connect(socket_path)
        .map_err(|e| format!(
            "Не удалось подключиться к {} — демон запущен? ({})",
            socket_path, e
        ))?;

    stream.set_write_timeout(Some(Duration::from_secs(5)))
        .map_err(|e| format!("set_write_timeout: {}", e))?;
    stream.set_read_timeout(Some(Duration::from_secs(10)))
        .map_err(|e| format!("set_read_timeout: {}", e))?;

    // Отправляем запрос
    let mut payload = serde_json::to_string(request)
        .map_err(|e| format!("serialization: {}", e))?;
    payload.push('\n');
    stream.write_all(payload.as_bytes())
        .map_err(|e| format!("write: {}", e))?;

    // Читаем ответ
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    reader.read_line(&mut line)
        .map_err(|e| format!("read: {}", e))?;

    // Разбираем и выводим
    let response: CtlResponse = serde_json::from_str(line.trim())
        .map_err(|e| format!("invalid response from daemon: {}", e))?;

    if response.ok {
        print_success(&response);
        Ok(())
    } else {
        Err(response.error.unwrap_or_else(|| "неизвестная ошибка".to_string()))
    }
}

#[derive(Debug, Deserialize)]
struct CtlResponse {
    ok: bool,
    data: Option<Value>,
    error: Option<String>,
}

#[derive(Debug, Deserialize)]
struct BlockedIpEntry {
    ip: String,
    blocked_at: i64,
    reason: String,
}

fn print_success(response: &CtlResponse) {
    let data = match &response.data {
        Some(d) => d,
        None => return,
    };

    // Если data — массив, это список IP (команда list)
    if let Some(entries) = data.as_array() {
        if entries.is_empty() {
            println!("Нет активных блоков.");
            return;
        }

        // Ширина столбцов
        let ip_width = entries.iter()
            .filter_map(|e| e.get("ip").and_then(|v| v.as_str()))
            .map(|s| s.len())
            .max()
            .unwrap_or(15)
            .max(15);

        println!(
            "{:<ip_width$}  {:<20}  {}",
            "IP", "Заблокирован", "Причина",
            ip_width = ip_width
        );
        println!("{}", "─".repeat(ip_width + 2 + 20 + 2 + 40));

        for entry in entries {
            if let Ok(e) = serde_json::from_value::<BlockedIpEntry>(entry.clone()) {
                let dt = format_timestamp(e.blocked_at);
                println!(
                    "{:<ip_width$}  {:<20}  {}",
                    e.ip, dt, e.reason,
                    ip_width = ip_width
                );
            }
        }
    } else if let Some(msg) = data.as_str() {
        // Команда unblock возвращает строку
        println!("{}", msg);
    }
}

fn format_timestamp(ts: i64) -> String {
    use std::time::{Duration, UNIX_EPOCH};
    let t = UNIX_EPOCH + Duration::from_secs(ts as u64);
    // Простое ISO-подобное форматирование без внешних зависимостей
    match std::time::SystemTime::now().duration_since(t) {
        Ok(elapsed) => {
            let secs = elapsed.as_secs();
            if secs < 60 {
                format!("{}s ago", secs)
            } else if secs < 3600 {
                format!("{}m ago", secs / 60)
            } else if secs < 86400 {
                format!("{}h ago", secs / 3600)
            } else {
                format!("{}d ago", secs / 86400)
            }
        }
        Err(_) => format!("ts:{}", ts),
    }
}
