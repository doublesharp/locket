"""Exercise the mutation runner without compiling mutated workspaces."""

import json
import os
import pathlib
import subprocess
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]


class MutationSmokeTests(unittest.TestCase):
    def test_every_security_area_selects_its_current_implementations(self):
        with tempfile.TemporaryDirectory() as directory:
            directory = pathlib.Path(directory)
            calls = directory / "calls.jsonl"
            runner = directory / "mutants.py"
            runner.write_text(
                "import json, os, sys\n"
                "if '--version' not in sys.argv:\n"
                "    with open(os.environ['MUTATION_TEST_CALLS'], 'a') as output:\n"
                "        output.write(json.dumps(sys.argv[1:]) + '\\n')\n"
            )
            result = subprocess.run(
                ["bash", "scripts/mutation-smoke.sh"],
                cwd=ROOT,
                env={
                    **os.environ,
                    "CARGO_MUTANTS": f"python3 {runner}",
                    "MUTATION_TEST_CALLS": str(calls),
                },
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            invocations = [json.loads(line) for line in calls.read_text().splitlines()]
            self.assertEqual(len(invocations), 4)
            expected = [
                {"crates/locket-core/src/policy/command.rs",
                 "crates/locket-agent/src/handlers/policies.rs"},
                {"crates/locket-cli/src/commands/exec/run.rs",
                 "crates/locket-agent/src/handlers/prepare_exec.rs"},
                {"crates/locket-core/src/error.rs",
                 "crates/locket-cli/src/runtime/error.rs"},
                {"crates/locket-agent/src/handlers/auth.rs",
                 "crates/locket-agent/src/state/grant.rs",
                 "crates/locket-store/src/access/grants.rs"},
            ]
            for arguments, required in zip(invocations, expected):
                selected = set()
                for index, argument in enumerate(arguments):
                    if argument == "--file":
                        pattern = arguments[index + 1]
                        matches = {str(path.relative_to(ROOT)) for path in ROOT.glob(pattern)}
                        self.assertTrue(matches, f"mutation filter matches no files: {pattern}")
                        selected.update(matches)
                self.assertLessEqual(required, selected)


if __name__ == "__main__":
    unittest.main()
