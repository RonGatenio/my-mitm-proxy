# Make protocols/ the import root so `import dumpparse`, `import _util`,
# `import cases.*` resolve under `python3 -m pytest` run from this directory.
import os, sys
sys.path.insert(0, os.path.dirname(__file__))
