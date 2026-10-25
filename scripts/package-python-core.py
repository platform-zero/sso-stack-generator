#!/usr/bin/env python3
"""Deterministic standard-library zipapp; no third-party build backend needed."""
import argparse
import hashlib
from pathlib import Path
import zipfile

parser = argparse.ArgumentParser()
parser.add_argument('--output', type=Path, required=True)
args = parser.parse_args()
root = Path(__file__).resolve().parents[1]
files = {path.relative_to(root).as_posix(): path.read_bytes() for path in sorted((root / 'p0core').glob('*.py'))}
files['__main__.py'] = b'from p0core.cli import main\nraise SystemExit(main())\n'
with args.output.open('xb') as destination:
    with zipfile.ZipFile(destination, 'w', compression=zipfile.ZIP_STORED) as archive:
        for name, content in sorted(files.items()):
            member = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            member.external_attr = 0o100444 << 16
            archive.writestr(member, content)
print(hashlib.sha256(args.output.read_bytes()).hexdigest())
