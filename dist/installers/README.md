# Native Installer Packaging

This directory describes the repository-side package builders for the public
desktop installers. Real signing still requires operator-held credentials:
Apple Developer ID Installer and notarization credentials, a Windows EV code
signing certificate, and Linux release GPG keys.

Local dry-run validation:

```sh
scripts/package-native-installers.sh --target all --dry-run
scripts/validate-distribution.sh
```

Release packaging commands:

```sh
scripts/package-native-installers.sh --target macos-pkg
scripts/package-native-installers.sh --target windows-msi
scripts/package-native-installers.sh --target linux-deb
scripts/package-native-installers.sh --target linux-rpm
```

Operator runbook commands:

```sh
scripts/release-operator-runbook.sh --task macos-pkg-sign-notarize-operator
scripts/release-operator-runbook.sh --task windows-msi-sign-operator
scripts/release-operator-runbook.sh --task linux-deb-rpm-sign-operator
```

These commands are dry-run by default. On credentialed platform hosts, add
`--execute --confirm publish-v0.1.0` after setting the signing environment
listed in `dist/installers/package-matrix.json`.

The canonical target list and signing inputs live in
`dist/installers/package-matrix.json`. CI runs the dry-run validator so
missing credentials do not block pull requests, while release operators get a
single concrete command per installer format.
