from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
PYTHON_SCRIPTS = ROOT / "scripts" / "python"
for path in (ROOT, PYTHON_SCRIPTS):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))
