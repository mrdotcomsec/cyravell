// Copyright 2026 Cyravell Contributors
// SPDX-License-Identifier: Apache-2.0

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::Duration;
use uuid::Uuid;

use crate::model::{
    GateEvaluateParams, GateEvaluateResult, GateRecordOutcomeParams, GateRecordOutcomeResult,
    JsonRpcRequest, JsonRpcResponse,
};

pub struct GateEngineClient {
    socket_path: PathBuf,
    timeout: Duration,
}

impl GateEngineClient {
    pub fn new<P: AsRef<Path>>(socket_path: P) -> Self {
        Self {
            socket_path: socket_path.as_ref().to_path_buf(),
            timeout: Duration::from_secs(3),
        }
    }

    pub fn with_timeout<P: AsRef<Path>>(socket_path: P, timeout: Duration) -> Self {
        Self {
            socket_path: socket_path.as_ref().to_path_buf(),
            timeout,
        }
    }

    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }

    pub fn is_available(&self) -> bool {
        UnixStream::connect(&self.socket_path).is_ok()
    }

    fn send_request(
        &self,
        method: &str,
        params: Option<serde_json::Value>,
    ) -> Result<JsonRpcResponse, String> {
        let mut stream = UnixStream::connect(&self.socket_path).map_err(|e| {
            format!(
                "Failed to connect to engine socket ({}): {}",
                self.socket_path.display(),
                e
            )
        })?;

        stream
            .set_read_timeout(Some(self.timeout))
            .map_err(|e| format!("Failed to set read timeout: {}", e))?;
        stream
            .set_write_timeout(Some(self.timeout))
            .map_err(|e| format!("Failed to set write timeout: {}", e))?;

        let request = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: serde_json::json!(Uuid::new_v4().to_string()),
            method: method.to_string(),
            params,
        };

        let req_bytes = serde_json::to_vec(&request)
            .map_err(|e| format!("Failed to serialize request: {}", e))?;

        stream
            .write_all(&req_bytes)
            .map_err(|e| format!("Failed to write to socket: {}", e))?;
        stream
            .write_all(b"\n")
            .map_err(|e| format!("Failed to write newline: {}", e))?;
        stream
            .flush()
            .map_err(|e| format!("Failed to flush socket: {}", e))?;

        let mut reader = BufReader::new(stream);
        let mut response_line = String::new();
        reader
            .read_line(&mut response_line)
            .map_err(|e| format!("Failed to read response from engine: {}", e))?;

        if response_line.trim().is_empty() {
            return Err("Empty response received from engine".to_string());
        }

        let response: JsonRpcResponse = serde_json::from_str(response_line.trim())
            .map_err(|e| format!("Invalid JSON response: {}", e))?;

        Ok(response)
    }

    pub fn evaluate(
        &self,
        command: &str,
        working_directory: Option<&str>,
        fail_closed: bool,
    ) -> Result<GateEvaluateResult, String> {
        let params = GateEvaluateParams {
            command: command.to_string(),
            working_directory: working_directory.map(|s| s.to_string()),
            fail_closed,
        };

        let resp =
            self.send_request("gate.evaluate", Some(serde_json::to_value(params).unwrap()))?;

        if let Some(err) = resp.error {
            return Err(format!("Engine error [{}]: {}", err.code, err.message));
        }

        let result_val = resp
            .result
            .ok_or_else(|| "Missing result in engine response".to_string())?;

        let res: GateEvaluateResult = serde_json::from_value(result_val)
            .map_err(|e| format!("Failed to deserialize GateEvaluateResult: {}", e))?;

        Ok(res)
    }

    pub fn record_outcome(
        &self,
        params: GateRecordOutcomeParams,
    ) -> Result<GateRecordOutcomeResult, String> {
        let resp = self.send_request(
            "gate.record_outcome",
            Some(serde_json::to_value(params).unwrap()),
        )?;

        if let Some(err) = resp.error {
            return Err(format!("Engine error [{}]: {}", err.code, err.message));
        }

        let result_val = resp
            .result
            .ok_or_else(|| "Missing result in engine response".to_string())?;

        let res: GateRecordOutcomeResult = serde_json::from_value(result_val)
            .map_err(|e| format!("Failed to deserialize GateRecordOutcomeResult: {}", e))?;

        Ok(res)
    }
}
