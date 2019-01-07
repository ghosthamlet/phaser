use std::process::Command;
use crate::scanner::scan;
use std::str;

pub enum State {
    Open,
    Closed,
}

pub struct Port {
    id: u16,
    state: State,
}

pub fn run(scan: scan::Scan) -> Result<Port, String> {
    let output = Command::new("echo")
        .arg("Hello world")
        .output()
        .expect("Failed to execute command");
    let _ = str::from_utf8(&output.stdout).unwrap();
    Ok(Port{id: 5432, state: State::Open})
}
