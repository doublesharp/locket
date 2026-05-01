# OS Host Validation

These checks cover behavior that repository CI can only probe, not fully prove,
because the final signal requires real OS prompts, signed installers, desktop
session state, or physical hardware.

## Local User Verification

Dry-run probe for CI and non-target hosts:

```sh
scripts/validate-local-user-auth-real-host.sh --dry-run
```

Linux Secret Service real-host validation:

```sh
scripts/validate-local-user-auth-real-host.sh --target linux-secret-service
```

Run once from an unlocked graphical session and once after locking the keyring
or session so the desktop unlock prompt is exercised.

Windows Hello real-host validation:

```sh
scripts/validate-local-user-auth-real-host.sh --target windows-hello
```

Run on an enrolled Windows user with an interactive desktop.

Linux FIDO2 hardware-key follow-up:

```sh
scripts/validate-local-user-auth-real-host.sh --target linux-secret-service --require-fido2
```

- [ ] Wire the production `libfido2-sys` user-presence ceremony behind the
  Linux fallback.
- [ ] Rerun the command above on a Linux host with a physical security key and
  record a successful touch.

## Packaged Canary Validation

Dry-run probe for CI:

```sh
scripts/validate-packaged-os-canaries.sh --dry-run
```

Release-host validation after installer and VSIX artifacts are produced:

```sh
LOCKET_PACKAGE_ARTIFACT_ROOT=target/package \
  scripts/validate-packaged-os-canaries.sh --install-smoke
```

The script scans package artifacts for known canary markers, verifies the host
installer signature or package metadata, and installs the packaged VSIX through
the `code` CLI when available.

Manual release follow-ups:

- [ ] Run signed desktop webview smoke on macOS, Windows, and Linux release
  hosts after installing the packaged desktop app.
- [ ] Exercise OS clipboard and tray integration on each installed desktop app.
- [ ] Run a full recovery restore e2e from the packaged CLI/app and scan the
  produced artifacts with the packaged-canary script.
