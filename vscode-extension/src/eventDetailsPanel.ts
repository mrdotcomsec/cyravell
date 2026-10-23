// Copyright 2026 Cyravell Contributors
// SPDX-License-Identifier: Apache-2.0

import * as vscode from 'vscode';
import { SecurityEventItem } from './engineClient';

export class EventDetailsPanel {
  public static currentPanel: EventDetailsPanel | undefined;
  private readonly panel: vscode.WebviewPanel;
  private disposables: vscode.Disposable[] = [];

  public static show(extensionUri: vscode.Uri, eventItem: SecurityEventItem) {
    const column = vscode.window.activeTextEditor
      ? vscode.window.activeTextEditor.viewColumn
      : undefined;

    if (EventDetailsPanel.currentPanel) {
      EventDetailsPanel.currentPanel.panel.reveal(column);
      EventDetailsPanel.currentPanel.update(eventItem);
      return;
    }

    const panel = vscode.window.createWebviewPanel(
      'cyravellEventDetails',
      `Cyravell: Event ${eventItem.event.id}`,
      column || vscode.ViewColumn.One,
      {
        enableScripts: false,
        retainContextWhenHidden: true,
      }
    );

    EventDetailsPanel.currentPanel = new EventDetailsPanel(panel, eventItem);
  }

  private constructor(panel: vscode.WebviewPanel, eventItem: SecurityEventItem) {
    this.panel = panel;
    this.update(eventItem);

    this.panel.onDidDispose(() => this.dispose(), null, this.disposables);
  }

  public update(eventItem: SecurityEventItem) {
    this.panel.title = `Cyravell Event: ${eventItem.event.id}`;
    this.panel.webview.html = this.renderHtml(eventItem);
  }

  public dispose() {
    EventDetailsPanel.currentPanel = undefined;
    this.panel.dispose();
    while (this.disposables.length) {
      const x = this.disposables.pop();
      if (x) {
        x.dispose();
      }
    }
  }

  private renderHtml(item: SecurityEventItem): string {
    const isSimulated = item.event.origin === 'SIMULATED';
    const evidenceList = item.assessment.evidence.map((e) => `<li><code>${escapeHtml(e)}</code></li>`).join('');
    const targetPaths = (item.event.payload.target_paths || []).map((p) => `<li><code>${escapeHtml(p)}</code></li>`).join('');

    const severityColor =
      item.assessment.severity === 'CRITICAL' ? '#d73a49' :
      item.assessment.severity === 'HIGH' ? '#e36209' :
      item.assessment.severity === 'MEDIUM' ? '#d9a700' : '#22863a';

    return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Cyravell Security Event</title>
  <style>
    body {
      font-family: var(--vscode-font-family);
      font-size: var(--vscode-font-size);
      color: var(--vscode-editor-foreground);
      background-color: var(--vscode-editor-background);
      padding: 24px;
      line-height: 1.6;
    }
    .badge {
      display: inline-block;
      padding: 4px 10px;
      border-radius: 4px;
      font-weight: 600;
      font-size: 12px;
      letter-spacing: 0.5px;
      text-transform: uppercase;
    }
    .badge-simulated {
      background-color: var(--vscode-badge-background);
      color: var(--vscode-badge-foreground);
      border: 1px solid var(--vscode-contrastBorder, transparent);
      margin-left: 8px;
    }
    .card {
      background: var(--vscode-editorWidget-background);
      border: 1px solid var(--vscode-widget-border, #333);
      border-radius: 6px;
      padding: 16px 20px;
      margin-bottom: 20px;
    }
    h2, h3 {
      margin-top: 0;
      color: var(--vscode-editor-foreground);
    }
    table {
      width: 100%;
      border-collapse: collapse;
      margin: 12px 0;
    }
    td {
      padding: 6px 10px;
      vertical-align: top;
    }
    td.label {
      width: 220px;
      font-weight: 600;
      color: var(--vscode-descriptionForeground);
    }
    code {
      font-family: var(--vscode-editor-font-family);
      background: var(--vscode-textCodeBlock-background);
      padding: 2px 6px;
      border-radius: 3px;
    }
    pre {
      background: var(--vscode-textCodeBlock-background);
      padding: 12px;
      border-radius: 4px;
      overflow-x: auto;
    }
  </style>
</head>
<body>
  <div style="display: flex; align-items: center; margin-bottom: 16px;">
    <h2>Security Event Details</h2>
    <span class="badge" style="background-color: ${severityColor}; color: #ffffff; margin-left: 16px;">
      ${escapeHtml(item.assessment.severity)}
    </span>
    ${isSimulated ? '<span class="badge badge-simulated">SIMULATED (TEST ONLY)</span>' : ''}
  </div>

  <div class="card">
    <h3>Deterministic Risk Assessment</h3>
    <table>
      <tr><td class="label">Rule ID:</td><td><code>${escapeHtml(item.assessment.rule_id)}</code></td></tr>
      <tr><td class="label">Reason:</td><td>${escapeHtml(item.assessment.reason)}</td></tr>
      <tr><td class="label">Recommended Action:</td><td><code>${escapeHtml(item.assessment.recommended_action)}</code></td></tr>
      <tr><td class="label">Confidence:</td><td>${escapeHtml(item.assessment.confidence)}</td></tr>
      <tr><td class="label">Evaluated At:</td><td>${escapeHtml(item.assessment.evaluated_at)}</td></tr>
    </table>
    <h4>Evidence</h4>
    <ul>${evidenceList.length ? evidenceList : '<li>None</li>'}</ul>
  </div>

  <div class="card">
    <h3>Event Context & Payload</h3>
    <table>
      <tr><td class="label">Event ID:</td><td><code>${escapeHtml(item.event.id)}</code></td></tr>
      <tr><td class="label">Event Type:</td><td><code>${escapeHtml(item.event.event_type)}</code></td></tr>
      <tr><td class="label">Source Adapter:</td><td><code>${escapeHtml(item.event.source_adapter)}</code></td></tr>
      <tr><td class="label">Execution Status:</td><td><code>${escapeHtml(item.event.execution_status)}</code></td></tr>
      <tr><td class="label">Enforcement Capability:</td><td><code>${escapeHtml(item.event.enforcement_capability)}</code></td></tr>
      <tr><td class="label">Working Directory:</td><td><code>${escapeHtml(item.event.payload.working_directory || 'N/A')}</code></td></tr>
    </table>
    <h4>Command Payload</h4>
    <pre><code>${escapeHtml(item.event.payload.command || '(no command string)')}</code></pre>
    ${targetPaths.length ? `<h4>Target Paths</h4><ul>${targetPaths}</ul>` : ''}
  </div>

  <div class="card">
    <h3>Cryptographic Audit Record</h3>
    <table>
      <tr><td class="label">Audit Sequence:</td><td><code>#${item.audit_sequence}</code></td></tr>
      <tr><td class="label">Record SHA-256 Hash:</td><td><code>${escapeHtml(item.audit_hash)}</code></td></tr>
      <tr><td class="label">Chain Storage:</td><td>Local append-only hash chain</td></tr>
    </table>
  </div>
</body>
</html>`;
  }
}

function escapeHtml(text: string): string {
  return text
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

