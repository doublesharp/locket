import * as vscode from 'vscode';

import { LocketDiagnosticContext, LocketDiagnosticPlan, locketDiagnosticPlans } from './diagnosticsModel';

const LOCKET_DIAGNOSTIC_SELECTOR: vscode.DocumentSelector = [
  { scheme: 'file', pattern: '**/.env' },
  { scheme: 'file', pattern: '**/.env.*' },
  { scheme: 'file', pattern: '**/.env.example' },
  { scheme: 'file', language: 'json' },
  { scheme: 'file', language: 'jsonc' },
  { scheme: 'file', language: 'toml' },
  { scheme: 'file', language: 'yaml' },
  { scheme: 'file', language: 'shellscript' },
  { scheme: 'file', language: 'javascript' },
  { scheme: 'file', language: 'javascriptreact' },
  { scheme: 'file', language: 'typescript' },
  { scheme: 'file', language: 'typescriptreact' },
  { scheme: 'file', language: 'python' },
  { scheme: 'file', language: 'rust' },
  { scheme: 'file', language: 'go' },
  { scheme: 'file', language: 'java' },
  { scheme: 'file', language: 'c' },
  { scheme: 'file', language: 'cpp' },
  { scheme: 'file', language: 'csharp' },
  { scheme: 'file', language: 'php' },
  { scheme: 'file', language: 'ruby' },
  { scheme: 'file', language: 'swift' },
  { scheme: 'file', language: 'kotlin' },
];

export interface LocketDiagnosticsController extends vscode.Disposable {
  updateContext(context: LocketDiagnosticContext | undefined): void;
  refreshVisibleDocuments(): void;
}

export function registerLocketDiagnostics(
  initialContext?: LocketDiagnosticContext,
): LocketDiagnosticsController {
  const collection = vscode.languages.createDiagnosticCollection('locket');
  const controller = new LocketDiagnostics(collection, initialContext);
  controller.refreshVisibleDocuments();
  return controller;
}

class LocketDiagnostics implements LocketDiagnosticsController {
  private context: LocketDiagnosticContext | undefined;
  private readonly disposables: vscode.Disposable[];

  public constructor(
    private readonly collection: vscode.DiagnosticCollection,
    initialContext: LocketDiagnosticContext | undefined,
  ) {
    this.context = initialContext;
    this.disposables = [
      collection,
      vscode.workspace.onDidOpenTextDocument((document) => this.refreshDocument(document)),
      vscode.workspace.onDidChangeTextDocument((event) => this.refreshDocument(event.document)),
      vscode.workspace.onDidCloseTextDocument((document) => this.collection.delete(document.uri)),
    ];
  }

  public updateContext(context: LocketDiagnosticContext | undefined): void {
    this.context = context;
    this.refreshVisibleDocuments();
  }

  public refreshVisibleDocuments(): void {
    for (const document of vscode.workspace.textDocuments) {
      this.refreshDocument(document);
    }
  }

  public dispose(): void {
    for (const disposable of this.disposables) {
      disposable.dispose();
    }
  }

  private refreshDocument(document: vscode.TextDocument): void {
    if (!matchesDiagnosticSelector(document)) {
      this.collection.delete(document.uri);
      return;
    }
    if (this.context === undefined) {
      this.collection.delete(document.uri);
      return;
    }
    const diagnostics = locketDiagnosticPlans(document.getText(), this.context).map((plan) =>
      toDiagnostic(document, plan),
    );
    this.collection.set(document.uri, diagnostics);
  }
}

function matchesDiagnosticSelector(document: vscode.TextDocument): boolean {
  return vscode.languages.match(LOCKET_DIAGNOSTIC_SELECTOR, document) > 0;
}

function toDiagnostic(document: vscode.TextDocument, plan: LocketDiagnosticPlan): vscode.Diagnostic {
  const diagnostic = new vscode.Diagnostic(
    new vscode.Range(document.positionAt(plan.startOffset), document.positionAt(plan.endOffset)),
    plan.message,
    diagnosticSeverity(plan.severity),
  );
  diagnostic.source = 'Locket';
  diagnostic.code = plan.code;
  return diagnostic;
}

function diagnosticSeverity(severity: LocketDiagnosticPlan['severity']): vscode.DiagnosticSeverity {
  switch (severity) {
    case 'error':
      return vscode.DiagnosticSeverity.Error;
    case 'warning':
      return vscode.DiagnosticSeverity.Warning;
  }
}
