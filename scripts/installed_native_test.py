#!/usr/bin/env python3
"""Regression tests that never invoke a system installer."""
import importlib.util
import os
import pathlib
import subprocess
import sys
import tempfile
import unittest

SCRIPT = pathlib.Path(__file__).with_name('validate-installed-native.py')


class NativeAcceptanceTests(unittest.TestCase):
    def load(self):
        self.assertTrue(SCRIPT.is_file(), 'native installation acceptance script is missing')
        spec = importlib.util.spec_from_file_location('native_acceptance', SCRIPT)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def temporary(self):
        # CI sets TMPDIR to runner.temp; local verification uses a Scratch path.
        return tempfile.TemporaryDirectory(dir=os.environ['TMPDIR'], prefix='installed-native-test-')

    def test_refuses_local_and_self_hosted_before_reading_or_running_installers(self):
        self.load()
        for flags in ({}, {'GITHUB_ACTIONS': 'true', 'RUNNER_ENVIRONMENT': 'self-hosted'}):
            env = {k: v for k, v in os.environ.items() if k not in ('GITHUB_ACTIONS', 'RUNNER_ENVIRONMENT')}
            env.update(flags)
            result = subprocess.run([sys.executable, str(SCRIPT), '--target', 'macos-pkg',
                                     '--installer-root', '/missing', '--scratch-root', '/missing',
                                     '--version', '0.1.0'], env=env, capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('GitHub-hosted disposable runner', result.stderr)

    def test_requires_paths_under_runner_temporary_directory(self):
        module = self.load()
        with self.temporary() as root:
            root = pathlib.Path(root)
            inside = root / 'inside'
            inside.mkdir()
            self.assertEqual(module.runner_path(inside, root), inside.resolve())
            with self.assertRaisesRegex(ValueError, 'runner temporary directory'):
                module.runner_path(root.parent, root)

    def test_selects_only_final_product_and_rejects_zero_or_multiple(self):
        module = self.load()
        with self.temporary() as root:
            root = pathlib.Path(root)
            (root / 'macos').mkdir()
            (root / 'macos/locket-component.pkg').touch()
            with self.assertRaisesRegex(ValueError, 'exactly one'):
                module.select_installer(root, 'macos-pkg', '0.1.0')
            product = root / 'macos/Locket-0.1.0-arm64-unsigned.pkg'
            product.touch()
            self.assertEqual(module.select_installer(root, 'macos-pkg', '0.1.0'), product)
            (root / 'macos/Locket-0.1.0-x86_64-unsigned.pkg').touch()
            with self.assertRaisesRegex(ValueError, 'exactly one'):
                module.select_installer(root, 'macos-pkg', '0.1.0')

    def test_version_check_executes_installed_cli_and_rejects_wrong_version(self):
        module = self.load()
        # Python is a real executable with a non-Locket --version response on
        # every CI OS. A zero exit code must not satisfy bundled CLI acceptance.
        with self.assertRaisesRegex(ValueError, 'CLI version mismatch'):
            module.verify_cli(pathlib.Path(sys.executable).resolve(), '0.1.0')

    def test_command_failure_propagates(self):
        module = self.load()
        with self.assertRaises(subprocess.CalledProcessError):
            module.run([sys.executable, '-c', 'raise SystemExit(19)'])

    def test_payload_scan_rejects_canary_split_across_read_boundary(self):
        module = self.load()
        with self.temporary() as root:
            file = pathlib.Path(root) / 'payload'
            file.write_bytes(b'x' * (1024 * 1024 - 4) + b'LOCKET_CANARY')
            with self.assertRaisesRegex(ValueError, 'canary marker'):
                module.scan_files([file])

    def test_debian_cli_discovery_uses_package_owned_paths_and_rejects_ambiguity(self):
        module = self.load()
        self.assertTrue(hasattr(module, 'debian_cli'), 'Debian CLI discovery is missing')
        with self.temporary() as root:
            root = pathlib.Path(root)
            paths = []
            for folder in ('Locket', 'locket-desktop'):
                cli = root / folder / 'locket'
                cli.parent.mkdir()
                cli.touch()
                paths.append(cli)
            self.assertEqual(module.debian_cli({paths[0]}), paths[0])
            self.assertEqual(module.debian_cli({paths[1]}), paths[1])
            with self.assertRaisesRegex(ValueError, 'exactly one'):
                module.debian_cli(set(paths))
            with self.assertRaisesRegex(ValueError, 'exactly one'):
                module.debian_cli(set())


if __name__ == '__main__':
    unittest.main()
