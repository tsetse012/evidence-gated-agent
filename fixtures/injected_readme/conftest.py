# Make the package importable without installing it.
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))