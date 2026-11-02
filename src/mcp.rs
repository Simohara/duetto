//! `--mcp`: a stdio MCP server that lets a model start or stop the running
//! Duetto window's bridge and set its volumes. It talks to the window over the
//! loopback control port, one JSON line each way; the window accepts only the
//! commands in `control_command`.
use serde_json::{Value, json};
use std::{
    io::{BufRead, BufReader, Write},
    net::{Ipv4Addr, SocketAddr, TcpStream},
    time::{Duration, Instant},
};

pub const CONTROL_PORT: u16 = 47391;

/// The page command for one control line, or None for anything outside the
/// allow-list. Volume is the only route field: pairing, delays and channels
/// stay with the window.
pub fn control_command(line: &str) -> Option<String> {
    let v: Value = serde_json::from_str(line).ok()?;
    let command = match v.get("cmd")?.as_str()? {
        "scan" => json!({ "cmd": "scan" }),
        "start" => json!({ "cmd": "start" }),
        "stop" => json!({ "cmd": "stop" }),
        "setMaster" => json!({ "cmd": "setMaster", "value": v.get("value")?.as_u64()?.min(100) }),
        "route" => json!({
            "cmd": "route",
            "address": v.get("address")?.as_str()?,
            "volume": v.get("volume")?.as_u64()?.min(100),
        }),
        _ => return None,
    };
    Some(command.to_string())
}

fn request(line: &str) -> Result<Value, String> {
    let address = SocketAddr::from((Ipv4Addr::LOCALHOST, CONTROL_PORT));
    let mut stream = TcpStream::connect_timeout(&address, Duration::from_secs(1))
        .map_err(|_| "Duetto is not running; open Duetto.exe first.".to_owned())?;
    stream.set_read_timeout(Some(Duration::from_secs(3))).ok();
    writeln!(stream, "{line}").map_err(|e| e.to_string())?;
    let mut reply = String::new();
    BufReader::new(stream)
        .read_line(&mut reply)
        .map_err(|e| e.to_string())?;
    let reply: Value = serde_json::from_str(&reply).map_err(|e| e.to_string())?;
    match reply.get("error").and_then(Value::as_str) {
        Some(error) => Err(error.to_owned()),
        None => Ok(reply),
    }
}

fn state() -> Result<Value, String> {
    request(r#"{"cmd":"state"}"#)
}

/// What a model needs to decide its next call; no ids or credentials.
fn summary(s: &Value) -> String {
    let speakers: Vec<Value> = s["speakers"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|x| {
            json!({
                "name": x["name"], "address": x["address"], "selected": x["selected"],
                "channel": match x["mode"].as_u64() { Some(1) => "left", Some(2) => "right", Some(3) => "mono", _ => "stereo" },
                "volume": x["volume"], "level": x["level"],
            })
        })
        .collect();
    serde_json::to_string_pretty(&json!({
        "run": s["run"], "master": s["master"], "status": s["status"],
        "session": s["session"], "speakers": speakers,
    }))
    .unwrap_or_default()
}

/// Polls until `done` holds or the time is up, then reports the last state.
fn wait_for(seconds: u64, done: impl Fn(&Value) -> bool) -> Result<String, String> {
    let until = Instant::now() + Duration::from_secs(seconds);
    loop {
        let s = state()?;
        if done(&s) || Instant::now() >= until {
            return Ok(summary(&s));
        }
        std::thread::sleep(Duration::from_millis(400));
    }
}

fn find_speaker(s: &Value, wanted: &str) -> Result<String, String> {
    let speakers = s["speakers"].as_array().cloned().unwrap_or_default();
    let name = |x: &Value| x["name"].as_str().unwrap_or("").to_lowercase();
    let wanted_lower = wanted.to_lowercase();
    let exact: Vec<_> = speakers
        .iter()
        .filter(|x| x["address"] == wanted || name(x) == wanted_lower)
        .collect();
    let hits = if exact.is_empty() {
        speakers
            .iter()
            .filter(|x| name(x).contains(&wanted_lower))
            .collect()
    } else {
        exact
    };
    match hits.as_slice() {
        [one] => Ok(one["address"].as_str().unwrap_or("").to_owned()),
        [] => Err(format!("No speaker matches “{wanted}”.")),
        _ => Err(format!(
            "“{wanted}” matches several speakers; use the address."
        )),
    }
}

fn call(name: &str, args: &Value) -> Result<String, String> {
    match name {
        "status" => Ok(summary(&state()?)),
        "connect" => {
            // A scan first, as in the window: it brings the speakers' current
            // addresses and lets Windows open the local network to the app.
            if state()?["busy"] == false {
                request(r#"{"cmd":"scan"}"#)?;
                std::thread::sleep(Duration::from_millis(500));
                wait_for(10, |s| s["scanning"] == false)?;
            }
            request(r#"{"cmd":"start"}"#)?;
            // Connecting a pair takes a few seconds; stop waiting once it is live or gave up.
            std::thread::sleep(Duration::from_millis(500));
            wait_for(20, |s| s["run"] == "live" || s["busy"] == false)
        }
        "disconnect" => {
            request(r#"{"cmd":"stop"}"#)?;
            wait_for(5, |s| s["busy"] == false)
        }
        "set_volume" => {
            let volume = args["volume"]
                .as_u64()
                .filter(|v| *v <= 100)
                .ok_or("volume must be a whole number from 0 to 100")?;
            match args["speaker"].as_str().filter(|s| !s.trim().is_empty()) {
                None => request(&json!({ "cmd": "setMaster", "value": volume }).to_string())?,
                Some(wanted) => {
                    let address = find_speaker(&state()?, wanted.trim())?;
                    request(
                        &json!({ "cmd": "route", "address": address, "volume": volume })
                            .to_string(),
                    )?
                }
            };
            std::thread::sleep(Duration::from_millis(300));
            Ok(summary(&state()?))
        }
        _ => Err(format!("Unknown tool {name}")),
    }
}

fn tools() -> Value {
    json!([
        {
            "name": "status",
            "description": "Duetto's bridge state (idle, connecting, live), master volume, status line and every speaker with its channel and volume.",
            "inputSchema": { "type": "object", "properties": {} }
        },
        {
            "name": "connect",
            "description": "Scan for speakers, then start bridging Windows audio (CABLE Output) to the speakers selected in Duetto. Waits until it is live or has failed, then returns the state.",
            "inputSchema": { "type": "object", "properties": {} }
        },
        {
            "name": "disconnect",
            "description": "Stop bridging and disconnect from the speakers.",
            "inputSchema": { "type": "object", "properties": {} }
        },
        {
            "name": "set_volume",
            "description": "Set the master volume (scales every speaker, keeping the calibrated balance) or, with `speaker`, one speaker's own volume. 0 to 100. Not available while a measurement or test tone runs.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "volume": { "type": "integer", "minimum": 0, "maximum": 100 },
                    "speaker": { "type": "string", "description": "Speaker name or address from `status`; omit for the master volume." }
                },
                "required": ["volume"]
            }
        }
    ])
}

fn respond(message: &Value) -> Option<Value> {
    let id = message.get("id")?.clone();
    let params = &message["params"];
    let result = match message["method"].as_str().unwrap_or("") {
        "initialize" => json!({
            "protocolVersion": params["protocolVersion"].as_str().unwrap_or("2025-06-18"),
            "capabilities": { "tools": {} },
            "serverInfo": { "name": "duetto", "version": env!("CARGO_PKG_VERSION") },
        }),
        "ping" => json!({}),
        "tools/list" => json!({ "tools": tools() }),
        "tools/call" => {
            let name = params["name"].as_str().unwrap_or("");
            let (text, error) = match call(name, &params["arguments"]) {
                Ok(text) => (text, false),
                Err(text) => (text, true),
            };
            json!({ "content": [{ "type": "text", "text": text }], "isError": error })
        }
        _ => {
            return Some(json!({
                "jsonrpc": "2.0", "id": id,
                "error": { "code": -32601, "message": "Method not found" },
            }));
        }
    };
    Some(json!({ "jsonrpc": "2.0", "id": id, "result": result }))
}

pub fn serve() -> Result<(), Box<dyn std::error::Error>> {
    let mut out = std::io::stdout().lock();
    for line in std::io::stdin().lock().lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let reply = match serde_json::from_str::<Value>(&line) {
            Ok(message) => respond(&message),
            Err(_) => Some(json!({
                "jsonrpc": "2.0", "id": null,
                "error": { "code": -32700, "message": "Parse error" },
            })),
        };
        // Notifications (no id) get no reply.
        if let Some(reply) = reply {
            writeln!(out, "{reply}")?;
            out.flush()?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_bridge_and_volume_commands_pass_the_control_port() {
        assert_eq!(
            control_command(r#"{"cmd":"start"}"#).unwrap(),
            r#"{"cmd":"start"}"#
        );
        assert_eq!(
            control_command(r#"{"cmd":"scan"}"#).unwrap(),
            r#"{"cmd":"scan"}"#
        );
        assert_eq!(
            control_command(r#"{"cmd":"setMaster","value":250}"#).unwrap(),
            r#"{"cmd":"setMaster","value":100}"#
        );
        // Extra route fields are dropped; volume is required.
        let route: Value = serde_json::from_str(
            &control_command(
                r#"{"cmd":"route","address":"a:7000","volume":40,"delay":900,"mode":1}"#,
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(
            route,
            json!({ "cmd": "route", "address": "a:7000", "volume": 40 })
        );
        for rejected in [
            r#"{"cmd":"route","address":"a:7000","delay":900}"#,
            r#"{"cmd":"pairDevice"}"#,
            r#"{"cmd":"setMaster","value":-1}"#,
            "GET / HTTP/1.1",
        ] {
            assert!(control_command(rejected).is_none(), "{rejected}");
        }
    }

    #[test]
    fn notifications_get_no_reply_and_unknown_methods_an_error() {
        assert!(
            respond(&json!({ "jsonrpc": "2.0", "method": "notifications/initialized" })).is_none()
        );
        let reply = respond(&json!({ "jsonrpc": "2.0", "id": 1, "method": "nope" })).unwrap();
        assert_eq!(reply["error"]["code"], -32601);
        let init = respond(&json!({ "jsonrpc": "2.0", "id": 2, "method": "initialize", "params": { "protocolVersion": "2025-03-26" } })).unwrap();
        assert_eq!(init["result"]["protocolVersion"], "2025-03-26");
        let list = respond(&json!({ "jsonrpc": "2.0", "id": 3, "method": "tools/list" })).unwrap();
        assert_eq!(list["result"]["tools"].as_array().unwrap().len(), 4);
    }

    #[test]
    fn speakers_are_found_by_address_exact_name_or_a_unique_part() {
        let s = json!({ "speakers": [
            { "name": "卧室 (2)", "address": "10.0.0.2:7000" },
            { "name": "卧室 (3)", "address": "10.0.0.3:7000" },
            { "name": "Study", "address": "10.0.0.4:7000" },
        ]});
        assert_eq!(find_speaker(&s, "10.0.0.3:7000").unwrap(), "10.0.0.3:7000");
        assert_eq!(find_speaker(&s, "卧室 (2)").unwrap(), "10.0.0.2:7000");
        assert_eq!(find_speaker(&s, "study").unwrap(), "10.0.0.4:7000");
        assert!(find_speaker(&s, "卧室").is_err());
        assert!(find_speaker(&s, "kitchen").is_err());
    }
}
