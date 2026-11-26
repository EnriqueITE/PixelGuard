const assert = require('node:assert/strict');
const test = require('node:test');
const vm = require('node:vm');
const fs = require('node:fs');
const path = require('node:path');

const source = path.join(__dirname, '../virustotal/inventory.js');
const sandbox = {URL};
vm.runInNewContext(fs.readFileSync(source, 'utf8'), sandbox, {filename: source});
const {collectLinks, validUrl, reportUrl} = sandbox.PixelGuardVTInventory;

function links(parts) {
  return Array.from(collectLinks(parts).links, item => item.url);
}

test('Gmail collects links in display order and only trims prose punctuation from text', () => {
  const article = 'https://example.test/Article_(part_2)';
  const literal = 'https://example.test/draft!';
  const ipv6 = 'https://[2001:db8::1]/index';
  const parts = [
    {hrefs: [literal, article, 'mailto:lab@example.test'], text: '(' + article + ').'},
    {hrefs: [], text: 'See [' + ipv6 + ']. (' + article + '). Or https://example.test/help.)].'}
  ];
  assert.deepEqual(links(parts), [literal, article, ipv6, 'https://example.test/help']);
});

test('Gmail checks the original candidate length before stripping punctuation', () => {
  const base = 'https://example.test/';
  const exact = base + 'a'.repeat(16384 - base.length);
  const next = 'https://example.test/next';
  assert.deepEqual(links([{hrefs: [], text: exact + '. ' + next}]), [next]);
  assert.deepEqual(links([{hrefs: [], text: exact}]), [exact]);
});

test('inventory truncation counts unique valid addresses and keeps the earliest ones', () => {
  const hrefs = Array.from({length: 1000}, (_, i) => 'https://example.test/' + i);
  const full = collectLinks([{hrefs, text: hrefs[0]}]);
  assert.equal(full.truncated, false);
  const limited = collectLinks([{hrefs, text: hrefs[0] + ' https://example.test/next'}]);
  assert.equal(limited.truncated, true);
  assert.deepEqual(Array.from(limited.links, item => item.url), hrefs);
});

test('Gmail retains HTTP address and HTTPS VirusTotal report restrictions', () => {
  assert.equal(validUrl('HTTP://EXAMPLE.TEST:80/doc').href, 'http://example.test/doc');
  assert.equal(validUrl('https://name:password@example.test/'), null);
  assert.equal(validUrl('file:///report.txt'), null);
  const report = 'https://www.virustotal.com/ui/widget/html/abc_1=';
  assert.equal(reportUrl(report), report);
  for (const invalid of [report + '?next=/other', report + '#ext', report + '/redirect',
    report.replace('https:', 'http:'), report.replace('www.virustotal.com', 'example.test')]) {
    assert.equal(reportUrl(invalid), null);
  }
});
