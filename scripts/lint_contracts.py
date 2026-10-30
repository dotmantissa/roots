import subprocess
from pathlib import Path
for path in sorted([*Path('contracts').glob('*.py'),*Path('tests/integration').glob('*.py')]):
    subprocess.run(['genvm-lint','check',str(path)],check=True)
