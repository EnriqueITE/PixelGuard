const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');

const source = path.join(__dirname, '../scanner.js');
const NodeFilter = {SHOW_ELEMENT: 1, SHOW_TEXT: 4, FILTER_ACCEPT: 1, FILTER_REJECT: 2, FILTER_SKIP: 3};
const sandbox = { URL, NodeFilter };
vm.runInNewContext(fs.readFileSync(source, 'utf8'), sandbox, { filename: source });
const { classifyImage, classifyLink, scanDocument } = sandbox.PixelGuardScanner;

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

function messageDocument(nodes) {
  return {createTreeWalker() {
    const iterator = nodes[Symbol.iterator]();
    return {nextNode() {
      this.currentNode = iterator.next().value;
      return this.currentNode;
    }};
  }};
}

function mailElement(localName, attributes) {
  return {nodeType: 1, localName, getAttribute: key => attributes[key] ?? null};
}

test('all image sources on one element reuse one visibility calculation', () => {
  const image = mailElement('img', {
    src: 'https://example.test/front.png',
    srcset: 'https://example.test/large.png 2x',
    style: "display:none; background-image: url('https://example.test/a.png'), URL(https://example.test/b.png)"
  });
  let styleReads = 0;
  image.ownerDocument = {defaultView: {getComputedStyle() { styleReads++; return {display: 'none'}; }}};
  const result = scanDocument(messageDocument([image]));
  assert.equal(styleReads, 1);
  assert.equal(result.partial, false);
  assert.equal(result.suspicious.length, 4);
  assert.ok(result.suspicious.every(item => item.signals.includes('display:none image')));
  image.ownerDocument.defaultView.getComputedStyle = () => ({display: 'block'});
  assert.equal(scanDocument(messageDocument([image])).externals.length, 4, 'Visibility is fresh on the next scan');
});

test('image dimensions participate in the field budget and are read once for all its sources', () => {
  const attributes = {
    src: 'https://example.test/illustration.png', srcset: 'https://example.test/illustration-large.png 2x',
    width: ' '.repeat(65536) + '1', height: '1'
  };
  const image = mailElement('img', attributes);
  const reads = {width: 0, height: 0};
  image.getAttribute = key => {
    if (key === 'width' || key === 'height') reads[key]++;
    return attributes[key] ?? null;
  };
  const skipped = scanDocument(messageDocument([image]));
  assert.equal(skipped.partial, true);
  assert.equal(skipped.externals.length, 2);
  assert.deepEqual(reads, {width: 1, height: 1});
  attributes.width = '1';
  const complete = scanDocument(messageDocument([image]));
  assert.equal(complete.partial, false);
  assert.equal(complete.suspicious.length, 2);
});

test('a skipped inline style is never re-read through the computed style fallback', () => {
  const image = mailElement('img', {src: 'https://example.test/front.png', style: ' '.repeat(65536) + 'display:none'});
  let reads = 0;
  image.ownerDocument = {defaultView: {getComputedStyle() { reads++; return {display: 'none'}; }}};
  const result = scanDocument(messageDocument([image]));
  assert.equal(result.partial, true);
  assert.equal(reads, 0);
  assert.equal(result.externals.length, 1);
});

test('text coverage changes at the link limit and preserves inspected results', () => {
  const text = count => ({nodeType: 3, nodeValue: Array.from({length: count}, (_, i) =>
    'https://click.example.test/news/' + i).join(' ')});
  assert.equal(scanDocument(messageDocument([text(50)])).partial, false);
  const result = scanDocument(messageDocument([text(51)]));
  assert.equal(result.partial, true);
  assert.equal(result.links.length, 50);
});

test('a text-node cutoff still inspects later image elements', () => {
  const text = Array.from({length: 502}, () => ({nodeType: 3, nodeValue: 'Newsletter paragraph.'}));
  const logo = mailElement('img', {src: 'https://example.test/logo.png'});
  const result = scanDocument(messageDocument([...text, logo]));
  assert.equal(result.partial, true);
  assert.equal(result.externals[0].url, 'https://example.test/logo.png');
});

test('one element reaching its image budget keeps its findings and the next image', () => {
  const layers = Array.from({length: 129}, (_, i) => 'url(https://example.test/image-' + i + '.png)');
  const backgrounds = mailElement('div', {style: 'background-image:' + layers.join(',')});
  const logo = mailElement('img', {src: 'https://example.test/logo.png'});
  const result = scanDocument(messageDocument([backgrounds, logo]));
  assert.equal(result.partial, true);
  assert.equal(result.externals.length, 129);
  assert.equal(result.externals.at(-1).url, 'https://example.test/logo.png');
});

test('the message-wide candidate budget stops traversal and keeps partial results', () => {
  const link = mailElement('a', {href: 'https://click.example.test/offer'});
  let visited = 0;
  function* links() {
    while (visited < 4200) { visited++; yield link; }
  }
  const result = scanDocument(messageDocument(links()));
  assert.equal(result.partial, true);
  assert.equal(result.links.length, 1);
  assert.equal(visited, 4097);
});

test('merging across sources preserves the strongest image and a link with the same URL', () => {
  const url = 'https://click.example.test/offer';
  const logo = mailElement('img', {src: url});
  const tiny = mailElement('img', {src: url, width: '1', height: '1'});
  const link = mailElement('a', {href: url});
  const visible = scanDocument(messageDocument([logo, tiny, link]));
  assert.equal(visible.externals.length, 0);
  assert.equal(visible.suspicious.length, 1);
  const original = scanDocument(messageDocument([logo, link]));
  const result = sandbox.PixelGuardScanner.mergeResults([original, visible]);
  assert.equal(result.suspicious[0], visible.suspicious[0]);
  assert.equal(result.links[0], original.links[0], 'Keep the first source on a tie');
  assert.equal(result.externals.length, 0);
  assert.equal(result.partial, false);
  assert.equal(sandbox.PixelGuardScanner.mergeResults([{...original, partial: true}, visible]).partial, true);
});
