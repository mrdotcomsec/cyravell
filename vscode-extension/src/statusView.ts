// Copyright 2026 Cyravell Contributors
// SPDX-License-Identifier: Apache-2.0

import * as vscode from 'vscode';
import { EngineClient, ConnectionState } from './engineClient';

export class StatusItem extends vscode.TreeItem {
  constructor(
    public readonly label: string,
    public readonly value: string,
    public readonly collapsibleState: vscode.TreeItemCollapsibleState,
    public readonly iconName?: string,
    public readonly tooltipText?: string
  ) {
    super(label, collapsibleState);
    this.description = value;
    this.tooltip = tooltipText || `${label}: ${value}`;
    if (iconName) {
      this.iconPath = new vscode.ThemeIcon(iconName);
    }
  }
}

export class StatusViewProvider implements vscode.TreeDataProvider<StatusItem> {
  private _onDidChangeTreeData: vscode.EventEmitter<StatusItem | undefined | null | void> = new vscode.EventEmitter<StatusItem | undefined | null | void>();
  readonly onDidChangeTreeData: vscode.Event<StatusItem | undefined | null | void> = this._onDidChangeTreeData.event;

  constructor(private client: EngineClient) {
    client.on('stateChanged', () => this.refresh());
    client.on('updated', () => this.refresh());
  }

  refresh(): void {
    this._onDidChangeTreeData.fire();
  }

  getTreeItem(element: StatusItem): vscode.TreeItem {
    return element;
  }

  getChildren(element?: StatusItem): Thenable<StatusItem[]> {
    if (element) {
      return Promise.resolve([]);
    }

    const state = this.client.getConnectionState();
    const items: StatusItem[] = [];

    // Connection status item
    if (state === 'CONNECTED') {
      const version = this.client.health ? `Engine v0.1.0` : 'Connected';
      items.push(
        new StatusItem(
          'Engine Connection',
          'CONNECTED',
          vscode.TreeItemCollapsibleState.None,
          'pass',
          `Connected to local Cyravell engine: ${version}`
        )
      );

      // Health metrics
      if (this.client.health) {
        items.push(
          new StatusItem(
            'Uptime',
            `${this.client.health.uptime_seconds}s`,
            vscode.TreeItemCollapsibleState.None,
            'clock'
          )
        );
        items.push(
          new StatusItem(
            'Events Processed',
            String(this.client.health.events_processed),
            vscode.TreeItemCollapsibleState.None,
            'pulse'
          )
        );
        items.push(
          new StatusItem(
            'Audit Records',
            String(this.client.health.audit_records_count),
            vscode.TreeItemCollapsibleState.None,
            'shield'
          )
        );
      }

      // Integrity status
      if (this.client.integrity) {
        const integrityIcon = this.client.integrity.status === 'verified' ? 'verified' : 'warning';
        items.push(
          new StatusItem(
            'Release Integrity',
            this.client.integrity.status.toUpperCase(),
            vscode.TreeItemCollapsibleState.None,
            integrityIcon,
            this.client.integrity.details
          )
        );
      }
    } else if (state === 'CONNECTING') {
      items.push(
        new StatusItem(
          'Engine Connection',
          'CONNECTING...',
          vscode.TreeItemCollapsibleState.None,
          'sync~spin',
          'Attempting connection to local IPC socket'
        )
      );
    } else if (state === 'DEGRADED') {
      items.push(
        new StatusItem(
          'Engine Connection',
          'DEGRADED',
          vscode.TreeItemCollapsibleState.None,
          'error',
          'Engine connection encountered integrity or protocol errors'
        )
      );
    } else {
      // DISCONNECTED
      items.push(
        new StatusItem(
          'Engine Connection',
          'DISCONNECTED',
          vscode.TreeItemCollapsibleState.None,
          'circle-slash',
          'Engine daemon is offline or socket unavailable. Never displays green when disconnected.'
        )
      );
    }

    // Socket path
    items.push(
      new StatusItem(
        'IPC Socket',
        this.client.getSocketPath(),
        vscode.TreeItemCollapsibleState.None,
        'plug',
        this.client.getSocketPath()
      )
    );

    // Terminal Interception Boundary
    const allTerminals = vscode.window.terminals || [];
    const protectedCount = allTerminals.filter((t) =>
      t.name.includes('Cyravell Protected Terminal')
    ).length;
    const ordinaryCount = allTerminals.length - protectedCount;

    items.push(
      new StatusItem(
        'Controlled Terminal Path',
        protectedCount > 0 ? `${protectedCount} Protected Active` : 'Available (Opt-In)',
        vscode.TreeItemCollapsibleState.None,
        protectedCount > 0 ? 'shield' : 'terminal',
        'Controlled terminal sessions intercept and gate commands before execution dispatch.'
      )
    );

    if (ordinaryCount > 0) {
      items.push(
        new StatusItem(
          'Ordinary Terminals',
          `${ordinaryCount} Active (UNPROTECTED)`,
          vscode.TreeItemCollapsibleState.None,
          'warning',
          'NOTICE: Ordinary terminal sessions bypass the Cyravell pre-execution gate. Use Cyravell Protected Terminal for active interception.'
        )
      );
    }

    return Promise.resolve(items);
  }
}

