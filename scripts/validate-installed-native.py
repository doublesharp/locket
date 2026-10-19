#!/usr/bin/env python3
"""Install an unsigned native package only on a disposable GitHub-hosted runner.

Checks installed package metadata, desktop executable and bundled CLI. This does
not launch the desktop UI or qualify signing, native authentication or UX.
"""
import argparse
import os
import pathlib
import platform
import plistlib
import re
import subprocess
import sys

CANARIES = (b'lk-canary', b'LOCKET_CANARY', b'DATABASE_URL_CANARY')


def scan_files(files):
    total = 0
    for file in files:
        if file.is_symlink():
            raise ValueError(f'installed package contains a symbolic link: {file}')
        if not file.is_file():
            continue
        with file.open('rb') as stream:
            tail = b''
            while block := stream.read(1024 * 1024):
                total += len(block)
                if total > 2 * 1024 * 1024 * 1024:
                    raise ValueError('installed payload exceeds acceptance scan limit')
                if any(marker in tail + block for marker in CANARIES):
                    raise ValueError(f'known canary marker in installed payload: {file}')
                tail = block[-64:]


def run(command, timeout=120):
    result = subprocess.run(command, check=True, capture_output=True, text=True, timeout=timeout)
    return result.stdout.strip()


def runner_path(path, runner_temp):
    path = pathlib.Path(path).resolve(strict=True)
    temporary = pathlib.Path(runner_temp).resolve(strict=True)
    if path == temporary or not path.is_relative_to(temporary) or not path.is_dir():
        raise ValueError('artifact and scratch roots must be directories inside the runner temporary directory')
    return path


def select_installer(root, target, version):
    pattern = {'macos-pkg': f'macos/Locket-{version}-*-unsigned.pkg',
               'windows-msi': f'windows/Locket-{version}-*.msi',
               'linux-deb': f'linux/locket_{version}_*.deb'}[target]
    matches = [p for p in root.glob(pattern) if p.is_file() and not p.is_symlink()]
    if len(matches) != 1:
        raise ValueError(f'expected exactly one final {target} installer, found {len(matches)}')
    return matches[0]


def verify_cli(cli, version):
    if not cli.is_file() or cli.is_symlink():
        raise ValueError(f'installed bundled CLI missing or is a link: {cli}')
    actual = run([str(cli), '--version'], timeout=10)
    if actual != f'locket {version}':
        raise ValueError(f'installed CLI version mismatch: expected locket {version}, got {actual!r}')


def install_macos(package, version, scratch):
    app = pathlib.Path('/Applications/Locket.app')
    if app.exists():
        raise ValueError('Locket.app already exists; acceptance requires a fresh runner')
    output = run(['sudo', '/usr/sbin/installer', '-pkg', str(package), '-target', '/'], timeout=180)
    (scratch / 'installer.log').write_text(output + '\n')
    receipt = plistlib.loads(subprocess.run(
        ['/usr/sbin/pkgutil', '--pkg-info-plist', 'app.locket.desktop.pkg'],
        check=True, capture_output=True, timeout=30).stdout)
    location = '/' + str(receipt.get('install-location', '')).lstrip('/')
    if receipt.get('pkg-version') != version or location != '/Applications':
        raise ValueError('installed macOS package receipt version/location mismatch')
    info = plistlib.loads((app / 'Contents/Info.plist').read_bytes())
    if info.get('CFBundleIdentifier') != 'app.locket.desktop' or info.get('CFBundleShortVersionString') != version:
        raise ValueError('installed macOS app identifier/version mismatch')
    executable = info.get('CFBundleExecutable')
    if not isinstance(executable, str) or not re.fullmatch(r'[A-Za-z0-9._-]+', executable):
        raise ValueError('invalid installed app executable name')
    if not (app / 'Contents/MacOS' / executable).is_file():
        raise ValueError('installed macOS desktop executable missing')
    scan_files(app.rglob('*'))
    verify_cli(app / 'Contents/Resources/locket', version)


def ps_literal(value):
    return "'" + str(value).replace("'", "''") + "'"


WINDOWS_READ_PROPERTY = r'''
function Read-Property($name) {
  $view = $database.OpenView("SELECT ``Value`` FROM ``Property`` WHERE ``Property`` = '$name'")
  [void] $view.Execute()
  $record = $view.Fetch()
  if ($null -eq $record) { throw "Missing MSI property $name" }
  $value = $record.StringData(1)
  [void] $view.Close()
  return $value
}
'''


def install_windows(package, version, scratch):
    destination = scratch / 'installed-Locket'
    if destination.exists():
        raise ValueError('MSI installation directory already exists; acceptance requires a fresh directory')
    # Tauri's WiX template names INSTALLDIR explicitly, stores resources below
    # that directory, and registers the ProductCode with Windows Installer.
    script = r'''
$ErrorActionPreference = 'Stop'
$msi = New-Object -ComObject WindowsInstaller.Installer
$database = $msi.OpenDatabase(PACKAGE_PATH, 0)
READ_PROPERTY_FUNCTION
$code = Read-Property 'ProductCode'
$productName = Read-Property 'ProductName'
if ($productName -ne 'Locket') { throw "Unexpected MSI product name: $productName" }
if ((Read-Property 'ProductVersion') -ne EXPECTED_VERSION) { throw 'Unexpected MSI product version' }
$arguments = '/i "' + PACKAGE_PATH + '" /qn /norestart /l*v "' + LOG_PATH + '" INSTALLDIR="' + INSTALL_PATH + '" AUTOLAUNCHAPP=""'
$process = Start-Process -FilePath 'msiexec.exe' -ArgumentList $arguments -Wait -PassThru
if ($process.ExitCode -notin @(0, 3010)) { throw "msiexec failed with exit $($process.ExitCode), see LOG_DESCRIPTION" }
if ($msi.ProductInfo($code, 'VersionString') -ne EXPECTED_VERSION) { throw 'Installed MSI registration version mismatch' }
Write-Output ('Installed MSI ' + $code + ', exit ' + $process.ExitCode)
'''
    substitutions = {'READ_PROPERTY_FUNCTION': WINDOWS_READ_PROPERTY,
                     'PACKAGE_PATH': ps_literal(package), 'EXPECTED_VERSION': ps_literal(version),
                     'LOG_PATH': ps_literal(scratch / 'msi-install.log'),
                     'INSTALL_PATH': ps_literal(destination),
                     'LOG_DESCRIPTION': 'msi-install.log'}
    for token, value in substitutions.items():
        script = script.replace(token, value)
    print(run(['powershell.exe', '-NoProfile', '-NonInteractive', '-Command', script], timeout=600))
    if not (destination / 'locket-desktop.exe').is_file():
        raise ValueError('installed Windows desktop executable missing')
    clis = [p for p in destination.rglob('locket.exe') if p.is_file()]
    if len(clis) != 1:
        raise ValueError(f'expected exactly one installed bundled Windows CLI, found {len(clis)}')
    scan_files(destination.rglob('*'))
    verify_cli(clis[0], version)


def debian_cli(package_files):
    clis = [p for p in package_files if p.name == 'locket' and p.is_file() and not p.is_symlink()]
    if len(clis) != 1:
        raise ValueError(f'expected exactly one installed package-owned Debian CLI, found {len(clis)}')
    return clis[0]


def install_linux(package, version, scratch):
    name = run(['dpkg-deb', '--field', str(package), 'Package'])
    actual = run(['dpkg-deb', '--field', str(package), 'Version'])
    if not re.fullmatch(r'[a-z0-9][a-z0-9+.-]+', name) or actual != version:
        raise ValueError('Debian package name/version mismatch')
    output = run(['sudo', 'apt-get', 'install', '-y', '--no-install-recommends', str(package)], timeout=300)
    (scratch / 'apt-install.log').write_text(output + '\n')
    installed = run(['dpkg-query', '-W', '-f=${Status}\n${Version}', name])
    if installed != f'install ok installed\n{version}':
        raise ValueError('installed Debian package status/version mismatch')
    files = {pathlib.Path(line) for line in run(['dpkg-query', '-L', name]).splitlines()}
    desktop = pathlib.Path('/usr/bin/locket-desktop')
    cli = debian_cli(files)
    entries = [p for p in files if p.parent == pathlib.Path('/usr/share/applications') and p.suffix == '.desktop']
    if desktop not in files or not desktop.is_file():
        raise ValueError('installed Debian desktop executable or bundled CLI missing from package files')
    if len(entries) != 1 or not entries[0].is_file():
        raise ValueError('expected exactly one installed desktop entry')
    linkage = run(['ldd', str(desktop)])
    if 'not found' in linkage:
        raise ValueError(f'installed desktop runtime dependency missing: {linkage}')
    # Only files owned by this package, never a recursive scan of /usr.
    scan_files(files)
    verify_cli(cli, version)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--target', choices=('host', 'macos-pkg', 'windows-msi', 'linux-deb'), default='host')
    parser.add_argument('--installer-root', required=True)
    parser.add_argument('--scratch-root', required=True, help='existing directory under RUNNER_TEMP for logs and MSI installation')
    parser.add_argument('--version', required=True)
    args = parser.parse_args()
    try:
        if os.environ.get('GITHUB_ACTIONS') != 'true' or os.environ.get('RUNNER_ENVIRONMENT') != 'github-hosted':
            raise ValueError('system installation requires a GitHub-hosted disposable runner')
        if not re.fullmatch(r'\d+\.\d+\.\d+', args.version):
            raise ValueError('native acceptance requires a numeric major.minor.patch version')
        runner_temp = os.environ.get('RUNNER_TEMP')
        if not runner_temp:
            raise ValueError('RUNNER_TEMP must identify the disposable runner temporary directory')
        root = runner_path(args.installer_root, runner_temp)
        scratch = runner_path(args.scratch_root, runner_temp)
        host = {'Darwin': 'macos-pkg', 'Windows': 'windows-msi', 'Linux': 'linux-deb'}.get(platform.system())
        target = host if args.target == 'host' else args.target
        if not target or target != host:
            raise ValueError('installer target must match the current runner OS')
        package = select_installer(root, target, args.version)
        {'macos-pkg': install_macos, 'windows-msi': install_windows, 'linux-deb': install_linux}[target](package, args.version, scratch)
    except (ValueError, KeyError, OSError, plistlib.InvalidFileException, subprocess.SubprocessError) as error:
        detail = getattr(error, 'stderr', '') or getattr(error, 'stdout', '')
        parser.exit(1, f'installed native acceptance failed: {error}\n{detail}')
    print(f'Installed native package and bundled CLI verified: {target} {args.version}')


if __name__ == '__main__':
    main()
