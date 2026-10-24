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

  client.on('stateChanged', () => updateStatusBar());
  client.on('updated', () => updateStatusBar());

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

        const items = pending.map((req) => ({
          label: `$(shield) ${req.command}`,
          description: `Severity: ${req.severity} | Rule: ${req.rule_id}`,
          detail: `Reason: ${req.reason} (Expires: ${new Date(req.expires_at).toLocaleTimeString()})`,
          request: req,
        }));

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

