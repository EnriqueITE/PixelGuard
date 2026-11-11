"""Validate the local XPI against the source allowlist, without loading private state."""
import hashlib
import json
from pathlib import Path
import zipfile

root = Path(__file__).resolve().parent.parent
manifest = json.loads((root / 'manifest.json').read_text(encoding='utf-8-sig'))
package = root / 'dist' / f"PixelGuard-{manifest['version']}.xpi"
included = ['manifest.json', 'background.js', 'virustotal', 'assets', 'content', 'options', 'popup', '_locales', 'icons']
expected = {}
for item in included:
    base = root / item
    paths = base.rglob('*') if base.is_dir() else [base]
    for file in paths:
        if file.is_file():
            assert not file.is_symlink(), f'Symlink not allowed: {file}'
            expected[file.relative_to(root).as_posix()] = file.read_bytes()
with zipfile.ZipFile(package) as archive:
    names = archive.namelist()
    assert len(names) == len(set(names)), 'Duplicate archive entry'
    assert set(names) == set(expected), 'Archive differs from runtime source allowlist'
    assert archive.testzip() is None, 'Corrupt archive'
    for name in names:
        assert not any(token in name.lower() for token in ['.env', 'profile', 'qa-tools', 'node_modules', '.git', 'credential']), name
        data = archive.read(name)
        assert data == expected[name], f'Packaged bytes differ: {name}'
        if name.endswith('.json'):
            json.loads(data.decode('utf-8-sig'))
print(json.dumps({'file': str(package), 'version': manifest['version'], 'files': len(expected),
                  'bytes': package.stat().st_size, 'sha256': hashlib.sha256(package.read_bytes()).hexdigest()}, indent=2))
