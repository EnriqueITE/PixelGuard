const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');

const source = path.join(__dirname, '../scanner.js');
const sandbox = { URL };
vm.runInNewContext(fs.readFileSync(source, 'utf8'), sandbox, { filename: source });
const { classifyImage, classifyLink } = sandbox.PixelGuardScanner;

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

test('Shop email click URLs retain their outer address and redirect evidence', () => {
  for (const token of ['-_8', '-_8=', 'YQ==']) {
    const url = 'https://mail.shop.app/_t/c/v3/' + token;
    const finding = classifyLink(url);
    assert.equal(finding.classification, 'tracking-link');
    assert.equal(finding.url, url);
    assert.deepEqual(Array.from(finding.signals), ['tracking/redirect path']);
  }
});

test('ordinary Shop pages, other hosts and embedded Shop URLs do not match the click route', () => {
  for (const url of [
    'https://shop.app/_t/c/v3/YQ',
    'https://mail.shop.app.example.test/_t/c/v3/YQ',
    'https://mail.shop.app@example.test/_t/c/v3/YQ',
    'http://mail.shop.app/_t/c/v3/YQ',
    'https://mail.shop.app/products/sample',
    'https://mail.shop.app/_t/open/YQ',
    'https://mail.shop.app/_t/c/v2/YQ',
    'https://mail.shop.app/_t/c/v3/',
    'https://mail.shop.app/_t/c/v3/YQ/extra',
    'https://mail.shop.app/_t/c/v3/Y=Q',
    'https://mail.shop.app/help#/_t/c/v3/YQ',
    'https://example.test/?next=https%3A%2F%2Fmail.shop.app%2F_t%2Fc%2Fv3%2FYQ'
  ]) {
    assert.equal(classifyLink(url), null, url);
  }
});

test('a hidden Shop open image is flagged when Gmail preserves its remote URL', () => {
  const url = 'https://mail.shop.app/_t/open/synthetic-id';
  const img = { getAttribute: name => name === 'style' ? 'display:none' : null };
  const finding = classifyImage(url, {}, img);
  assert.equal(finding.classification, 'tracking-pixel');
  assert.ok(finding.signals.includes('display:none image'));
  assert.ok(finding.signals.includes('open path'));
  assert.equal(classifyImage('', {}, img), null);
});
