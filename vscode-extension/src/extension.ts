// Copyright 2026 Cyravell Contributors
// SPDX-License-Identifier: Apache-2.0

import * as vscode from 'vscode';
import { EngineClient, SecurityEventItem } from './engineClient';
import { StatusViewProvider } from './statusView';
import { EventsViewProvider } from './eventsView';
import { EventDetailsPanel } from './eventDetailsPanel';

let client: EngineClient | undefined;
let statusBarItem: vscode.StatusBarItem;

export function activate(context: vscode.ExtensionContext) {
  const config = vscode.workspace.getConfiguration('cyravell');
  const customSocket = config.get<string>('cyravell.socketPath') || undefined;

  client = new EngineClient(customSocket);

  // Status Bar Item
  statusBarItem = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 100);
  statusBarItem.command = 'cyravell.refreshStatus';
  context.subscriptions.push(statusBarItem);
  updateStatusBar();

  const notifiedEventIds = new Set<string>();
  let isInitialLoad = true;
  let previousConnectionState = client.getConnectionState();

  client.on('stateChanged', (newState) => {
    updateStatusBar();
    if (newState === 'CONNECTED' && previousConnectionState !== 'CONNECTED') {
      vscode.window.showInformationMessage('Cyravell Security Engine: Connected and active.');
    }
    previousConnectionState = newState;
  });

  client.on('updated', () => {
    updateStatusBar();

    if (!client) {
      return;
    }

    const events = client.recentEvents;
    if (isInitialLoad) {
      for (const ev of events) {
        notifiedEventIds.add(ev.event.id);
      }
      isInitialLoad = false;
      return;
    }

    for (const item of events) {
      if (notifiedEventIds.has(item.event.id)) {
        continue;
      }
      notifiedEventIds.add(item.event.id);

      const sev = item.assessment.severity;
      const cmd = item.event.payload.command ? ` | Command: ${item.event.payload.command}` : '';
      const rule = item.assessment.rule_id;
      const reason = item.assessment.reason;

      if (item.event.execution_status === 'PENDING_APPROVAL') {
        vscode.window
          .showWarningMessage(
            `[Cyravell Approval Required] ${reason}${cmd}`,
            'Review Approvals',
            'Inspect Event'
          )
          .then((action) => {
            if (action === 'Review Approvals') {
              vscode.commands.executeCommand('cyravell.reviewApprovals');
            } else if (action === 'Inspect Event') {
              vscode.commands.executeCommand('cyravell.inspectEvent', item);
            }
          });
      } else if (sev === 'CRITICAL') {
        vscode.window
          .showErrorMessage(
            `[Cyravell Alert] CRITICAL: ${reason} [${rule}]${cmd}`,
            'Inspect Event'
          )
          .then((action) => {
            if (action === 'Inspect Event') {
              vscode.commands.executeCommand('cyravell.inspectEvent', item);
            }
          });
      } else if (sev === 'HIGH') {
        vscode.window
          .showWarningMessage(
            `[Cyravell Alert] HIGH: ${reason} [${rule}]${cmd}`,
            'Inspect Event'
          )
          .then((action) => {
            if (action === 'Inspect Event') {
              vscode.commands.executeCommand('cyravell.inspectEvent', item);
            }
          });
      }
    }
  });

  // Views
  const statusProvider = new StatusViewProvider(client);
  const eventsProvider = new EventsViewProvider(client);

  vscode.window.registerTreeDataProvider('cyravell.statusView', statusProvider);
  vscode.window.registerTreeDataProvider('cyravell.eventsView', eventsProvider);

  // Commands
  context.subscriptions.push(
    vscode.commands.registerCommand('cyravell.connect', async () => {
      vscode.window.showInformationMessage('Connecting to Cyravell security engine...');
      const success = await client!.connect();
      if (success) {
        vscode.window.showInformationMessage('Successfully connected to Cyravell engine.');
      } else {
        vscode.window.showErrorMessage(
          `Unable to connect to Cyravell engine at ${client!.getSocketPath()}. Ensure the engine daemon is running.`
        );
      }
    })
  );

  context.subscriptions.push(
    vscode.commands.registerCommand('cyravell.disconnect', () => {
      client!.disconnect();
      vscode.window.showInformationMessage('Disconnected from Cyravell security engine.');
    })
  );

  context.subscriptions.push(
    vscode.commands.registerCommand('cyravell.refreshStatus', async () => {
      try {
        if (client!.getConnectionState() !== 'CONNECTED') {
          await client!.connect();
        } else {
          await client!.refresh();
        }
      } catch (e: any) {
        vscode.window.showErrorMessage(`Cyravell refresh failed: ${e.message}`);
      }
    })
  );

  context.subscriptions.push(
    vscode.commands.registerCommand('cyravell.verifyAudit', async () => {
      try {
        const result = await client!.verifyAudit();
        if (result.status === 'VALID') {
          vscode.window.showInformationMessage(
            `Cyravell Audit Verified: ${result.total_records} records in valid cryptographic chain.`
          );
        } else {
          vscode.window.showErrorMessage(
            `Cyravell Audit Corrupted! Tampering detected at sequence #${result.corrupted_sequence}: ${result.message}`
          );
        }
      } catch (e: any) {
        vscode.window.showErrorMessage(`Audit verification failed: ${e.message}`);
      }
    })
  );

  context.subscriptions.push(
    vscode.commands.registerCommand('cyravell.inspectEvent', (item?: SecurityEventItem) => {
      if (!item) {
        vscode.window.showInformationMessage('Select a security event from the list to inspect.');
        return;
      }
      EventDetailsPanel.show(context.extensionUri, item);
    })
  );

  context.subscriptions.push(
    vscode.commands.registerCommand('cyravell.openControlledTerminal', () => {
      const termConfig = vscode.workspace.getConfiguration('cyravell.controlledTerminal');
      if (!termConfig.get<boolean>('enabled', true)) {
        vscode.window.showWarningMessage('Cyravell controlled terminal is disabled in settings.');
        return;
      }

      const binaryPath = termConfig.get<string>('engineBinary', 'cyravell-engine');
      const failClosed = termConfig.get<boolean>('failClosed', true);
      const args = ['shell'];
      if (failClosed) {
        args.push('--fail-closed');
      }

      const terminal = vscode.window.createTerminal({
        name: 'Cyravell Protected Terminal',
        shellPath: binaryPath,
        shellArgs: args,
      });

      terminal.show();
      statusProvider.refresh();
      vscode.window.showInformationMessage(
        'Launched Cyravell Protected Terminal. Commands in this terminal are intercepted and evaluated before execution dispatch.'
      );
    })
  );

  context.subscriptions.push(
    vscode.commands.registerCommand('cyravell.reviewApprovals', async () => {
      try {
        if (!client || client.getConnectionState() !== 'CONNECTED') {
          vscode.window.showWarningMessage('Cyravell engine is not connected.');
          return;
        }

        const pending = await client.getPendingApprovals();
        if (pending.length === 0) {
          vscode.window.showInformationMessage('No commands currently pending approval.');
          return;
        }

        const items = pending.map((req) => {
          let desc = `Severity: ${req.severity} | Rule: ${req.rule_id}`;
          let detail = `Reason: ${req.reason}`;
          if (req.package_details) {
            desc = `Package: ${req.package_details.package_manager} (${req.package_details.operation}) | Severity: ${req.severity} | Findings: ${req.package_details.findings_count}`;
            const pkgNames = req.package_details.findings.map((f) => f.package_name).join(', ');
            detail = `Findings: [${pkgNames}] ${req.reason}`;
          }
          detail += ` (Expires: ${new Date(req.expires_at).toLocaleTimeString()})`;
          return {
            label: `$(shield) ${req.command}`,
            description: desc,
            detail: detail,
            request: req,
          };
        });

        const selected = await vscode.window.showQuickPick(items, {
          placeHolder: 'Select a pending command to review',
        });

        if (!selected) {
          return;
        }

        const decision = await vscode.window.showQuickPick(
          [
            { label: 'Approve', description: 'Grant single-use authorization for exact command' },
            { label: 'Deny', description: 'Prevent command execution' },
            { label: 'Cancel', description: 'Cancel pending approval request' },
          ],
          { placeHolder: `Action for: ${selected.request.command}` }
        );

        if (!decision) {
          return;
        }

        const userDecision = decision.label as 'Approve' | 'Deny' | 'Cancel';
        const res = await client.decideApproval(
          selected.request.request_id,
          userDecision,
          'User decision via VS Code dialog'
        );

        vscode.window.showInformationMessage(
          `Decision recorded: ${res.status}. ${res.message}`
        );
        statusProvider.refresh();
      } catch (e: any) {
        vscode.window.showErrorMessage(`Approval action failed: ${e.message}`);
      }
    })
  );

  context.subscriptions.push(
    vscode.commands.registerCommand('cyravell.createBaseline', async () => {
      try {
        if (!client || client.getConnectionState() !== 'CONNECTED') {
          vscode.window.showWarningMessage('Cyravell engine is not connected.');
          return;
        }

        const wsFolders = vscode.workspace.workspaceFolders;
        if (!wsFolders || wsFolders.length === 0) {
          vscode.window.showWarningMessage('No workspace folder open.');
          return;
        }

        const wsPath = wsFolders[0].uri.fsPath;
        const res = await client.createBaseline(wsPath, undefined, 'VERIFIED_APPROVED');
        vscode.window.showInformationMessage(
          `Dependency baseline created for ${res.baseline.ecosystem}: ${res.message} (Fingerprint: ${res.baseline.baseline_fingerprint.substring(0, 12)}...)`
        );
        statusProvider.refresh();
      } catch (e: any) {
        vscode.window.showErrorMessage(`Failed to create baseline: ${e.message}`);
      }
    })
  );

  context.subscriptions.push(
    vscode.commands.registerCommand('cyravell.reconcileDrift', async () => {
      try {
        if (!client || client.getConnectionState() !== 'CONNECTED') {
          vscode.window.showWarningMessage('Cyravell engine is not connected.');
          return;
        }

        const wsFolders = vscode.workspace.workspaceFolders;
        if (!wsFolders || wsFolders.length === 0) {
          vscode.window.showWarningMessage('No workspace folder open.');
          return;
        }

        const wsPath = wsFolders[0].uri.fsPath;
        const res = await client.detectDrift(wsPath, true);
        const report = res.drift_report;
        if (report.findings.length === 0) {
          const bp = report.trusted_baseline_fingerprint || report.current_fingerprint;
          vscode.window.showInformationMessage(
            `Workspace dependency check: Clean. Zero drift detected against baseline ${bp.substring(0, 12)}...`
          );
        } else {
          const names = report.findings.map((f) => `${f.package_name} (${f.change_type})`).join(', ');
          vscode.window.showWarningMessage(
            `Dependency drift detected! ${report.findings.length} findings: ${names}. Summary: ${report.summary}`
          );
        }
        statusProvider.refresh();
      } catch (e: any) {
        vscode.window.showErrorMessage(`Failed to check dependency drift: ${e.message}`);
      }
    })
  );

  context.subscriptions.push(
    vscode.commands.registerCommand('cyravell.inspectAdvisories', async () => {
      try {
        const fileUris = await vscode.window.showOpenDialog({
          canSelectMany: false,
          openLabel: 'Inspect Advisory Bundle',
          filters: { 'JSON Files': ['json'] },
        });
        if (!fileUris || fileUris.length === 0) {
          return;
        }
        const filePath = fileUris[0].fsPath;
        const res = await client!.inspectAdvisoryBundle(filePath);
        vscode.window.showInformationMessage(
          `Advisory Bundle: v${res.database_version} by ${res.publisher}. Valid: ${res.is_valid}, Signature: ${res.signature_valid}. Advisories: ${res.records_count} (+${res.new_records.length}, ~${res.updated_records.length}, -${res.removed_records.length}). ${res.summary}`
        );
      } catch (e: any) {
        vscode.window.showErrorMessage(`Failed to inspect advisory bundle: ${e.message}`);
      }
    })
  );

  context.subscriptions.push(
    vscode.commands.registerCommand('cyravell.importAdvisories', async () => {
      try {
        const fileUris = await vscode.window.showOpenDialog({
          canSelectMany: false,
          openLabel: 'Import Advisory Bundle',
          filters: { 'JSON Files': ['json'] },
        });
        if (!fileUris || fileUris.length === 0) {
          return;
        }
        const filePath = fileUris[0].fsPath;
        const inspection = await client!.inspectAdvisoryBundle(filePath);
        let allowRollback = false;
        if (inspection.would_rollback) {
          const choice = await vscode.window.showWarningMessage(
            `Candidate version ${inspection.candidate_version} is older than or equal to active version ${inspection.active_version}. Allow rollback?`,
            { modal: true },
            'Allow Rollback',
            'Cancel'
          );
          if (choice !== 'Allow Rollback') {
            return;
          }
          allowRollback = true;
        }

        const res = await client!.importAdvisoryBundle(filePath, allowRollback);
        vscode.window.showInformationMessage(
          `Advisory bundle v${res.new_version} activated! Total advisories: ${res.records_count}, Reassessed baselines: ${res.affected_workspaces.length}. Status: ${res.message}`
        );
        statusProvider.refresh();
      } catch (e: any) {
        vscode.window.showErrorMessage(`Failed to import advisory bundle: ${e.message}`);
      }
    })
  );

  // Monitor terminal sessions for honest status reporting
  context.subscriptions.push(vscode.window.onDidOpenTerminal(() => statusProvider.refresh()));
  context.subscriptions.push(vscode.window.onDidCloseTerminal(() => statusProvider.refresh()));

  // Auto connect if configured
  if (config.get<boolean>('cyravell.autoConnect', true)) {
    client.connect();
  }
}

function updateStatusBar() {
  if (!client || !statusBarItem) {
    return;
  }

  const state = client.getConnectionState();
  switch (state) {
    case 'CONNECTED': {
      const count = client.health?.events_processed ?? 0;
      statusBarItem.text = `$(shield) Cyravell: Active (${count} events)`;
      statusBarItem.tooltip = `Cyravell Security Engine Connected\nUptime: ${client.health?.uptime_seconds ?? 0}s\nIntegrity: ${client.integrity?.status ?? 'unknown'}`;
      statusBarItem.backgroundColor = undefined;
      break;
    }
    case 'CONNECTING':
      statusBarItem.text = '$(sync~spin) Cyravell: Connecting...';
      statusBarItem.tooltip = 'Attempting connection to local IPC socket';
      statusBarItem.backgroundColor = undefined;
      break;
    case 'DEGRADED':
      statusBarItem.text = '$(warning) Cyravell: Degraded';
      statusBarItem.tooltip = 'Engine reports degraded health or integrity failure';
      statusBarItem.backgroundColor = new vscode.ThemeColor('statusBarItem.warningBackground');
      break;
    case 'DISCONNECTED':
    default:
      // CRITICAL REQUIREMENT: Never display green or active when disconnected!
      statusBarItem.text = '$(circle-slash) Cyravell: Offline';
      statusBarItem.tooltip = 'Security engine daemon is not connected. Monitoring is inactive.';
      statusBarItem.backgroundColor = new vscode.ThemeColor('statusBarItem.errorBackground');
      break;
  }
  statusBarItem.show();
}

export function deactivate() {
  if (client) {
    client.disconnect();
  }
}

