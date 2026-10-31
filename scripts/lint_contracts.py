import os
import subprocess
from pathlib import Path

# Match the direct-test SDK bundle; contract headers still select exact hashes.
environment = dict(os.environ, GENVM_VERSION='v0.2.16')
for path in sorted([*Path('contracts').glob('*.py'),*Path('tests/integration').glob('*.py')]):
    subprocess.run(['genvm-lint','check',str(path)],check=True,env=environment)
