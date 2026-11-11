const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const manifest = JSON.parse(fs.readFileSync('manifest.json', 'utf8'));

test('release manifest uses only expected public permissions and bundled background scripts', () => {
  assert.equal(manifest.version, '0.2.0');
  assert.equal(manifest.manifest_version, 2);
  assert.equal(manifest.browser_specific_settings.gecko.strict_min_version, '115.0');
  assert.equal(manifest.experiment_apis, undefined);
  assert.equal(manifest.content_security_policy, undefined, 'Keep the default extension CSP');
  assert.deepEqual(manifest.permissions, ['messagesRead', 'messagesModify', 'storage']);
  assert.deepEqual(manifest.optional_permissions, ['sensitiveDataUpload', 'https://www.virustotal.com/*']);
  for (const file of manifest.background.scripts) {
    assert.ok(!file.includes('..') && !file.includes('://'));
    assert.ok(fs.existsSync(file));
  }
});

function files(dir) {
  return fs.readdirSync(dir, { withFileTypes: true }).flatMap(entry => entry.isDirectory() ? files(path.join(dir, entry.name)) : [path.join(dir, entry.name)]);
}
test('bundled source has no Experiments, remote scripts, iframe or dynamic code execution', () => {
  for (const file of ['background.js', ...['virustotal', 'content', 'options', 'popup'].flatMap(files)]) {
    if (!/\.(js|html)$/.test(file)) continue;
    const source = fs.readFileSync(file, 'utf8');
    assert.doesNotMatch(source, /\b(?:eval\s*\(|new\s+Function\s*\(|ChromeUtils\.|Components\.|experiment_apis)/, file);
    assert.doesNotMatch(source, /<iframe\b|<script\b[^>]*\bsrc\s*=\s*["'](?:https?:)?\/\//i, file);
  }
});

test('all bundled locales provide the VT UI messages and required substitutions', () => {
  const canonical = JSON.parse(fs.readFileSync('_locales/en/messages.json', 'utf8'));
  const keys = Object.keys(canonical).filter(k => k.startsWith('vt_'));
  assert.ok(keys.length > 20);
  for (const locale of fs.readdirSync('_locales')) {
    const messages = JSON.parse(fs.readFileSync(`_locales/${locale}/messages.json`, 'utf8'));
    for (const key of keys) {
      assert.ok(messages[key]?.message, `${locale}: ${key}`);
      const slots = s => [...s.matchAll(/\$[1-9]/g)].map(m => m[0]).sort();
      assert.deepEqual(slots(messages[key].message), slots(canonical[key].message), `${locale}: ${key} substitutions`);
    }
  }
});
