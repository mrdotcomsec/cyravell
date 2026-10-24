// Copyright 2026 Cyravell Contributors
// SPDX-License-Identifier: Apache-2.0

import * as net from 'net';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { EventEmitter } from 'events';

export type ConnectionState = 'DISCONNECTED' | 'CONNECTING' | 'CONNECTED' | 'DEGRADED';

export interface HealthInfo {
  status: string;
  uptime_seconds: number;
  events_processed: number;
  audit_records_count: number;
  degraded_reasons: string[];
}

export interface IntegrityInfo {
  status: string;
  manifest_version: string;
  verified_files_count: number;
  details: string;
}

export interface CommandAnalysisDetails {
  raw_command: string;
  sanitized_command: string;
  atomic_commands_count: number;
  operators_detected: string[];
  command_names: string[];
  potential_impact?: string;
  analysis_notes: string[];
}

export interface PackageSecurityFinding {
  package_name: string;
  version?: string;
  advisory_id: string;
  title: string;
  severity: string;
  is_malicious: boolean;
  affected_range: string;
  fixed_version?: string;
  details: string;
}

export interface PackageAssessmentSummary {
  package_manager: string;
  operation: string;
  status: string;
  findings_count: number;
  critical_count: number;
  high_count: number;
  malicious_count: number;
  findings: PackageSecurityFinding[];
  manifest_fingerprint?: string;
}

export interface PackageAssessmentResult {
  package_manager: string;
  operation: string;
  status: string;
  direct_packages: string[];
  total_dependencies_scanned: number;
  findings: PackageSecurityFinding[];
  manifest_fingerprint?: string;
  inspected_files: string[];
  assessment_source: string;
  offline_mode: boolean;
  notes: string[];
}

export interface GateEvaluateResult {
  decision: 'ALLOW' | 'REQUIRE_APPROVAL' | 'BLOCK' | 'ANALYSIS_FAILED';
  outcome:
    | 'DISPATCHED'
    | 'BLOCKED_BY_POLICY'
    | 'PENDING_APPROVAL'
    | 'FAILED_CLOSED'
    | 'EXECUTION_FAILED'
    | 'DENIED_BY_USER'
    | 'CANCELLED_BY_USER'
    | 'EXPIRED_APPROVAL';
  risk_assessment: any;
  analysis_completeness: string;
  request_id?: string;
  session_id?: string;
  audit_sequence?: number;
  audit_record_hash?: string;
  reason: string;
  allow_dispatch: boolean;
  package_assessment?: PackageAssessmentResult;
}

export interface ApprovalRequestItem {
  request_id: string;
  session_id: string;
  command: string;
  working_directory?: string;
  rule_id: string;
  severity: string;
  reason: string;
  created_at: string;
  expires_at: string;
  status: string;
  decision_reason?: string;
  package_details?: PackageAssessmentSummary;
  manifest_fingerprint?: string;
}

export interface ApprovalDecideResult {
  request_id: string;
  status: string;
  authorization_token?: string;
  message: string;
  audit_sequence?: number;
}

export interface GateDispatchAuthorizedResult {
  request_id: string;
  dispatched: boolean;
  exit_code?: number;
  outcome: string;
  audit_sequence: number;
  audit_record_hash: string;
  message: string;
}

export interface SecurityEventItem {
  event: {
    id: string;
    schema_version: number;
    timestamp: string;
    event_type: string;
    source_adapter: string;
    origin: string;
    execution_status: string;
    enforcement_capability: string;
    payload: {
      command?: string;
      working_directory?: string;
      target_paths?: string[];
      metadata?: Record<string, string>;
    };
  };
  assessment: {
    severity: 'INFO' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
    confidence: 'LOW' | 'MEDIUM' | 'HIGH';
    rule_id: string;
    reason: string;
    evidence: string[];
    recommended_action: string;
    evaluated_at: string;
    matched_rules?: string[];
    potential_impact?: string;
    analysis_completeness?: 'COMPLETE' | 'PARTIAL' | 'INCONCLUSIVE';
    analysis_details?: CommandAnalysisDetails;
  };
  audit_sequence: number;
  audit_hash: string;
}

export interface AuditVerifyResult {
  status: string;
  total_records: number;
  genesis_hash: string;
  latest_hash: string;
  corrupted_sequence?: number | null;
  message: string;
}

export class EngineClient extends EventEmitter {
  private socket: net.Socket | null = null;
  private state: ConnectionState = 'DISCONNECTED';
  private socketPath: string;
  private pendingRequests: Map<string, { resolve: (val: any) => void; reject: (err: any) => void }> = new Map();
  private buffer = '';
  private reqIdCounter = 0;
  private pollInterval: NodeJS.Timeout | null = null;

  public health: HealthInfo | null = null;
  public integrity: IntegrityInfo | null = null;
  public recentEvents: SecurityEventItem[] = [];

  constructor(customSocketPath?: string) {
    super();
    this.socketPath = customSocketPath || this.resolveDefaultSocketPath();
  }

  public getConnectionState(): ConnectionState {
    return this.state;
  }

  public getSocketPath(): string {
    return this.socketPath;
  }

  public setSocketPath(newPath: string) {
    this.socketPath = newPath;
    if (this.state === 'CONNECTED' || this.state === 'CONNECTING') {
      this.disconnect();
      this.connect();
    }
  }

  private resolveDefaultSocketPath(): string {
    if (process.env.XDG_RUNTIME_DIR) {
      return path.join(process.env.XDG_RUNTIME_DIR, 'cyravell', 'cyravell.sock');
    }
    const uid = process.getuid ? process.getuid() : 1000;
    return `/tmp/cyravell-${uid}/cyravell.sock`;
  }

  public connect(): Promise<boolean> {
    if (this.state === 'CONNECTED' || this.state === 'CONNECTING') {
      return Promise.resolve(true);
    }

    this.setState('CONNECTING');

    return new Promise((resolve) => {
      if (!fs.existsSync(this.socketPath)) {
        this.setState('DISCONNECTED');
        resolve(false);
        return;
      }

      const socket = net.createConnection(this.socketPath);
      this.socket = socket;

      socket.on('connect', async () => {
        try {
          const handshake = await this.call('engine.handshake', {
            client_name: 'vscode-cyravell',
            client_version: '0.1.0',
            protocol_version: '1.0',
          });

          if (handshake && handshake.status === 'ready') {
            this.setState('CONNECTED');
            await this.refresh();
            this.startPolling();
            resolve(true);
          } else {
            this.setState('DEGRADED');
            resolve(false);
          }
        } catch (e) {
          this.setState('DEGRADED');
          resolve(false);
        }
      });

      socket.on('data', (chunk) => {
        this.buffer += chunk.toString('utf-8');
        let newlineIndex: number;
        while ((newlineIndex = this.buffer.indexOf('\n')) !== -1) {
          const line = this.buffer.slice(0, newlineIndex).trim();
          this.buffer = this.buffer.slice(newlineIndex + 1);
          if (line.length > 0) {
            this.handleMessage(line);
          }
        }
      });

      socket.on('error', (err) => {
        this.cleanupSocket();
        this.setState('DISCONNECTED');
        resolve(false);
      });

      socket.on('close', () => {
        this.cleanupSocket();
        this.setState('DISCONNECTED');
      });
    });
  }

  public disconnect() {
    this.stopPolling();
    this.cleanupSocket();
    this.setState('DISCONNECTED');
  }

  private cleanupSocket() {
    if (this.socket) {
      this.socket.removeAllListeners();
      this.socket.destroy();
      this.socket = null;
    }
    for (const [, req] of this.pendingRequests) {
      req.reject(new Error('Connection closed'));
    }
    this.pendingRequests.clear();
    this.buffer = '';
  }

  private setState(newState: ConnectionState) {
    if (this.state !== newState) {
      this.state = newState;
      this.emit('stateChanged', newState);
    }
  }

  private startPolling() {
    this.stopPolling();
    this.pollInterval = setInterval(async () => {
      if (this.state === 'CONNECTED') {
        try {
          await this.refresh();
        } catch (_) {
          this.setState('DEGRADED');
        }
      }
    }, 3000);
  }

  private stopPolling() {
    if (this.pollInterval) {
      clearInterval(this.pollInterval);
      this.pollInterval = null;
    }
  }

  public async refresh(): Promise<void> {
    if (this.state !== 'CONNECTED') {
      return;
    }
    try {
      const [health, integrity, recent] = await Promise.all([
        this.call('engine.get_health', {}),
        this.call('engine.get_integrity', {}),
        this.call('event.get_recent', { limit: 50 }),
      ]);
      this.health = health;
      this.integrity = integrity;
      this.recentEvents = (recent && recent.events) ? recent.events : [];
      this.emit('updated');
    } catch (e) {
      this.setState('DEGRADED');
      throw e;
    }
  }

  public async verifyAudit(): Promise<AuditVerifyResult> {
    if (this.state !== 'CONNECTED') {
      throw new Error('Engine is not connected');
    }
    return this.call('audit.verify', {});
  }

  public async analyzeCommand(command: string, workingDirectory?: string): Promise<any> {
    if (this.state !== 'CONNECTED') {
      throw new Error('Engine is not connected');
    }
    return this.call('command.analyze', {
      command,
      working_directory: workingDirectory,
    });
  }

  public async evaluateGate(
    command: string,
    workingDirectory?: string,
    failClosed = true
  ): Promise<GateEvaluateResult> {
    if (this.state !== 'CONNECTED') {
      throw new Error('Engine is not connected');
    }
    return this.call('gate.evaluate', {
      command,
      working_directory: workingDirectory,
      fail_closed: failClosed,
    });
  }

  public async getPendingApprovals(sessionId?: string): Promise<ApprovalRequestItem[]> {
    if (this.state !== 'CONNECTED') {
      throw new Error('Engine is not connected');
    }
    const res = await this.call('approval.get_pending', { session_id: sessionId });
    return res && res.pending_requests ? res.pending_requests : [];
  }

  public async decideApproval(
    requestId: string,
    decision: 'Approve' | 'Deny' | 'Cancel',
    reason?: string
  ): Promise<ApprovalDecideResult> {
    if (this.state !== 'CONNECTED') {
      throw new Error('Engine is not connected');
    }
    return this.call('approval.decide', {
      request_id: requestId,
      decision,
      reason,
    });
  }

  public async dispatchAuthorized(
    requestId: string,
    sessionId: string,
    command: string,
    authorizationToken: string,
    workingDirectory?: string
  ): Promise<GateDispatchAuthorizedResult> {
    if (this.state !== 'CONNECTED') {
      throw new Error('Engine is not connected');
    }
    return this.call('gate.dispatch_authorized', {
      request_id: requestId,
      session_id: sessionId,
      command,
      authorization_token: authorizationToken,
      working_directory: workingDirectory,
    });
  }

  public call(method: string, params: any): Promise<any> {
    return new Promise((resolve, reject) => {
      if (!this.socket || this.socket.destroyed) {
        return reject(new Error('Socket is not connected'));
      }

      const id = String(++this.reqIdCounter);
      const req = {
        jsonrpc: '2.0',
        id,
        method,
        params,
      };

      this.pendingRequests.set(id, { resolve, reject });

      const payload = JSON.stringify(req) + '\n';
      this.socket.write(payload, 'utf-8', (err) => {
        if (err) {
          this.pendingRequests.delete(id);
          reject(err);
        }
      });
    });
  }

  private handleMessage(raw: string) {
    try {
      const msg = JSON.parse(raw);
      if (msg.id && this.pendingRequests.has(msg.id)) {
        const { resolve, reject } = this.pendingRequests.get(msg.id)!;
        this.pendingRequests.delete(msg.id);

        if (msg.error) {
          reject(new Error(`Engine error [${msg.error.code}]: ${msg.error.message}`));
        } else {
          resolve(msg.result);
        }
      }
    } catch (e) {
      console.error('Failed to parse IPC message from Cyravell engine', e);
    }
  }
}

