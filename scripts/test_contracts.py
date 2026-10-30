"""Run isolated contract tests with an ephemeral signing identity, never production keys."""
import os
import secrets
import subprocess
import sys

environment = dict(os.environ)
environment['DEPLOYER_PRIVATE_KEY'] = '0x' + secrets.token_hex(32)
result = subprocess.run([sys.executable, '-m', 'pytest', 'tests/direct', 'tests/validator', '-q'], env=environment)
raise SystemExit(result.returncode)
