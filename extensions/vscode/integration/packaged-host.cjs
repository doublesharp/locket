// Run by VS Code's extension test host against the installed VSIX.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vscode = require('vscode');

exports.run = async () => {
  const id = process.env.LOCKET_EXPECTED_EDITOR_ID;
  const version = process.env.LOCKET_EXPECTED_EDITOR_VERSION;
  const report = process.env.LOCKET_EDITOR_ACCEPTANCE_REPORT;
  assert.ok(id && version && report, 'explicit isolated acceptance inputs required');
  const extension = vscode.extensions.getExtension(id);
  assert.ok(extension, 'installed Locket extension must be discovered');
  assert.equal(extension.packageJSON.version, version);
  await extension.activate();
  assert.ok(extension.isActive, 'installed extension must activate');
  const commands = new Set(await vscode.commands.getCommands(true));
  const expected = ['unlock', 'lock', 'switchProfile', 'runPolicy', 'scanWorkspace',
    'revealSecret', 'copySecret', 'openAuditView', 'createTerminal'].map(name => 'locket.' + name);
  for (const command of expected) assert.ok(commands.has(command), 'missing command ' + command);
  fs.writeFileSync(report, JSON.stringify({ id, version, isActive: true,
    extensionPath: extension.extensionPath, registeredCommands: expected }, null, 2));
};
