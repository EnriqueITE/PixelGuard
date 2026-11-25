const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');

const source = path.join(__dirname, '../scanner.js');
const sandbox = { URL };
vm.runInNewContext(fs.readFileSync(source, 'utf8'), sandbox, { filename: source });
const { classifyLink } = sandbox.PixelGuardScanner;

function amazonLink(host = 'www.amazon.es', route = '/gp/f.html') {
  const wrapper = new URL(route, 'https://' + host);
  wrapper.search = new URLSearchParams({ M: 'sample', R: 'test', U: 'https://example.test/product', T: 'C' });
  return wrapper;
}

test('a complete Amazon click redirect retains its outer address and tracking evidence', () => {
  for (const [host, route] of [['amazon.es', '/gp/f.html'], ['www.amazon.es', '/gp/r.html'], ['www.amazon.co.uk', '/gp/f.html']]) {
    const wrapper = amazonLink(host, route);
    const finding = classifyLink(wrapper.href);
    assert.equal(finding.url, wrapper.href);
    assert.equal(finding.host, host);
    assert.equal(finding.classification, 'tracking-link');
    assert.equal(finding.reason, 'tracking/redirect path');
  }
});

test('lookalike sites, product pages and incomplete Amazon redirects stay unflagged', () => {
  for (const host of ['amazon.es.example.test', 'notamazon.es', 'amazon.example', 'unrelated.amazon.es']) {
    assert.equal(classifyLink(amazonLink(host).href), null, host);
  }
  assert.equal(classifyLink(amazonLink('www.amazon.es', '/dp/example-product').href), null);
  for (const key of ['T', 'M', 'R', 'U']) {
    const candidate = amazonLink();
    candidate.searchParams.delete(key);
    assert.equal(classifyLink(candidate.href), null, key);
  }
  for (const [key, value] of [['T', 'A'], ['M', ''], ['U', 'relative/path'], ['U', 'https://'], ['U', 'ftp://example.test']]) {
    const candidate = amazonLink();
    candidate.searchParams.set(key, value);
    assert.equal(classifyLink(candidate.href), null, key + '=' + value);
  }
});
