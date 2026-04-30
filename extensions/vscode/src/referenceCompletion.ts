import * as vscode from 'vscode';

import { AgentClient } from './agentClient';
import {
  REFERENCE_COMPLETION_TRIGGER_CHARACTERS,
  ReferenceCompletionPlan,
  locateReferenceFragment,
  referenceCompletionPlans,
} from './referenceCompletionModel';

const REFERENCE_DOCUMENT_SELECTOR: vscode.DocumentSelector = [
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

export function registerReferenceCompletionProvider(agentClient: AgentClient): vscode.Disposable {
  return vscode.languages.registerCompletionItemProvider(
    REFERENCE_DOCUMENT_SELECTOR,
    new LocketReferenceCompletionProvider(agentClient),
    ...REFERENCE_COMPLETION_TRIGGER_CHARACTERS,
  );
}

class LocketReferenceCompletionProvider implements vscode.CompletionItemProvider {
  public constructor(private readonly agentClient: AgentClient) {}

  public async provideCompletionItems(
    document: vscode.TextDocument,
    position: vscode.Position,
  ): Promise<vscode.CompletionItem[] | undefined> {
    const linePrefix = document.lineAt(position.line).text.slice(0, position.character);
    const fragment = locateReferenceFragment(linePrefix);
    if (fragment === undefined) {
      return undefined;
    }
    const activeProfileName = await this.activeProfileName();
    const range = new vscode.Range(position.line, fragment.startOffset, position.line, position.character);
    return referenceCompletionPlans(fragment.text, activeProfileName).map((plan) => completionItem(plan, range));
  }

  private async activeProfileName(): Promise<string | null> {
    try {
      const status = await this.agentClient.status();
      return status.profile_name ?? null;
    } catch {
      return null;
    }
  }
}

function completionItem(plan: ReferenceCompletionPlan, range: vscode.Range): vscode.CompletionItem {
  const item = new vscode.CompletionItem(plan.label, completionItemKind(plan.kind));
  item.insertText = new vscode.SnippetString(plan.insertText);
  item.range = range;
  item.detail = plan.detail;
  return item;
}

function completionItemKind(kind: ReferenceCompletionPlan['kind']): vscode.CompletionItemKind {
  switch (kind) {
    case 'reference':
      return vscode.CompletionItemKind.Reference;
    case 'source':
      return vscode.CompletionItemKind.EnumMember;
    case 'version':
      return vscode.CompletionItemKind.Value;
  }
}
