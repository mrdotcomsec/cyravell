// Copyright 2026 Cyravell Contributors
// SPDX-License-Identifier: Apache-2.0

import * as vscode from 'vscode';
import { EngineClient, SecurityEventItem } from './engineClient';

export class EventTreeItem extends vscode.TreeItem {
  constructor(public readonly eventItem: SecurityEventItem) {
    const isSimulated = eventItem.event.origin === 'SIMULATED';
    const simPrefix = isSimulated ? '[SIMULATED] ' : '';
    const label = `${simPrefix}${eventItem.assessment.severity}: ${eventItem.event.event_type}`;

    super(label, vscode.TreeItemCollapsibleState.None);

    const cmd = eventItem.event.payload.command ? ` | ${eventItem.event.payload.command}` : '';
    this.description = `#${eventItem.audit_sequence} ${eventItem.assessment.rule_id}${cmd}`;
    this.tooltip = new vscode.MarkdownString(
      `### ${simPrefix}${eventItem.assessment.severity} Risk Alert\n\n` +
      `**Event ID:** \`${eventItem.event.id}\`\n\n` +
      `**Origin:** \`${eventItem.event.origin}\`\n\n` +
      `**Status:** \`${eventItem.event.execution_status}\`\n\n` +
      `**Rule:** \`${eventItem.assessment.rule_id}\`\n\n` +
      `**Reason:** ${eventItem.assessment.reason}\n\n` +
      `**Recommended Action:** \`${eventItem.assessment.recommended_action}\`\n\n` +
      `**Audit Hash:** \`${eventItem.audit_hash}\``
    );

    // Pick severity icon
    switch (eventItem.assessment.severity) {
      case 'CRITICAL':
        this.iconPath = new vscode.ThemeIcon('error', new vscode.ThemeColor('errorForeground'));
        break;
      case 'HIGH':
        this.iconPath = new vscode.ThemeIcon('warning', new vscode.ThemeColor('problemsWarningIcon.foreground'));
        break;
      case 'MEDIUM':
        this.iconPath = new vscode.ThemeIcon('info', new vscode.ThemeColor('problemsInfoIcon.foreground'));
        break;
      case 'LOW':
      default:
        this.iconPath = new vscode.ThemeIcon('check', new vscode.ThemeColor('charts.blue'));
        break;
    }

    this.command = {
      command: 'cyravell.inspectEvent',
      title: 'Inspect Security Event',
      arguments: [eventItem],
    };
  }
}

export class EventsViewProvider implements vscode.TreeDataProvider<vscode.TreeItem> {
  private _onDidChangeTreeData: vscode.EventEmitter<vscode.TreeItem | undefined | null | void> = new vscode.EventEmitter<vscode.TreeItem | undefined | null | void>();
  readonly onDidChangeTreeData: vscode.Event<vscode.TreeItem | undefined | null | void> = this._onDidChangeTreeData.event;

  constructor(private client: EngineClient) {
    client.on('updated', () => this.refresh());
    client.on('stateChanged', () => this.refresh());
  }

  refresh(): void {
    this._onDidChangeTreeData.fire();
  }

  getTreeItem(element: vscode.TreeItem): vscode.TreeItem {
    return element;
  }

  getChildren(element?: vscode.TreeItem): Thenable<vscode.TreeItem[]> {
    if (element) {
      return Promise.resolve([]);
    }

    const state = this.client.getConnectionState();
    if (state !== 'CONNECTED') {
      const emptyItem = new vscode.TreeItem(
        state === 'DISCONNECTED' ? 'Engine disconnected — events unavailable' : 'Connecting to Cyravell engine...',
        vscode.TreeItemCollapsibleState.None
      );
      emptyItem.iconPath = new vscode.ThemeIcon('circle-slash');
      return Promise.resolve([emptyItem]);
    }

    if (this.client.recentEvents.length === 0) {
      const emptyItem = new vscode.TreeItem('No security events recorded yet', vscode.TreeItemCollapsibleState.None);
      emptyItem.iconPath = new vscode.ThemeIcon('info');
      return Promise.resolve([emptyItem]);
    }

    const items = this.client.recentEvents.map((e) => new EventTreeItem(e));
    return Promise.resolve(items);
  }
}

