const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const test = require('node:test');

const source = fs.readFileSync('content/scanner.js', 'utf8');
const sandbox = { URL, console };
vm.runInNewContext(source, sandbox, { filename: 'content/scanner.js' });
const scanner = sandbox.PixelGuardScanner;

class FakeElement {
  constructor(attrs, ownerDocument) {
    this.attrs = attrs;
    this.ownerDocument = ownerDocument;
  }
  getAttribute(name) {
    return this.attrs[name] || '';
  }
  getBoundingClientRect() {
    if (this.attrs['data-box-width'] || this.attrs['data-box-height']) {
      return {
        width: Number.parseFloat(this.attrs['data-box-width'] || '0'),
        height: Number.parseFloat(this.attrs['data-box-height'] || '0')
      };
    }
    const width = Number.parseFloat(this.attrs.width || '') || styleNumber(this.attrs.style, 'width') || 100;
    const height = Number.parseFloat(this.attrs.height || '') || styleNumber(this.attrs.style, 'height') || 100;
    return { width, height };
  }
}

function styleNumber(style, prop) {
  const match = String(style || '').match(new RegExp(`${prop}\\s*:\\s*(\\d+(?:\\.\\d+)?)px?`, 'i'));
  return match ? Number(match[1]) : 0;
}

function parseAttrs(tag) {
  const attrs = {};
  const attrRe = /([\w-]+)\s*=\s*"([^"]*)"/g;
  let match;
  while ((match = attrRe.exec(tag))) attrs[match[1]] = match[2];
  return attrs;
}

function fakeDocument(html) {
  const doc = {
    body: {},
    defaultView: {
      getComputedStyle(el) {
        const style = el.getAttribute('style') || '';
        const read = (prop, fallback = '') => {
          const match = style.match(new RegExp(`${prop}\\s*:\\s*([^;]+)`, 'i'));
          return match ? match[1].trim() : fallback;
        };
        return {
          display: read('display', 'block'),
          visibility: read('visibility', 'visible'),
          opacity: read('opacity', '1')
        };
      }
    },
    querySelectorAll(selector) {
      if (selector === 'img') {
        return Array.from(html.matchAll(/<img\b[^>]*>/gi), m => new FakeElement(parseAttrs(m[0]), doc));
      }
      if (selector === 'a[href]') {
        return Array.from(html.matchAll(/<a\b[^>]*>/gi), m => new FakeElement(parseAttrs(m[0]), doc));
      }
      if (selector === '[style*="url("]') {
        return Array.from(html.matchAll(/<\w+\b[^>]*style="[^"]*url\([^>]*>/gi), m => new FakeElement(parseAttrs(m[0]), doc));
      }
      return [];
    }
  };
  return doc;
}

function scan(html, senderDomain = 'example.com') {
  return scanner.scanDocument(fakeDocument(html), { senderDomain });
}

test('visible campaign image is external, not a tracking pixel', () => {
  const result = scan('<img src="https://cdn.example.com/banner.jpg?utm_campaign=sale" width="600" height="300">');
  assert.equal(result.suspicious.length, 0);
  assert.equal(result.externals.length, 1);
  assert.equal(result.externals[0].classification, 'external-image');
});

test('remote 1x1 image is a probable tracking pixel', () => {
  const result = scan('<img src="https://img.vendor.net/p.gif" width="1" height="1">');
  assert.equal(result.suspicious.length, 1);
  assert.equal(result.suspicious[0].classification, 'tracking-pixel');
  assert.equal(result.suspicious[0].reason, 'explicit 1x1 image');
});

test('hidden image with recipient id is high confidence', () => {
  const result = scan('<img src="https://events.vendor.net/open.gif?uid=abc" style="display:none">');
  assert.equal(result.suspicious.length, 1);
  assert.equal(result.suspicious[0].classification, 'tracking-pixel');
  assert.equal(result.suspicious[0].confidence, 'high');
  assert.equal(result.suspicious[0].reason, 'display:none image with recipient id');
});

test('tiny image with open path has a specific reason', () => {
  const result = scan('<img src="https://events.vendor.net/open/logo.gif" width="2" height="2">');
  assert.equal(result.suspicious.length, 1);
  assert.equal(result.suspicious[0].classification, 'tracking-pixel');
  assert.equal(result.suspicious[0].reason, 'tiny image with open path');
});

test('visible image with open path only is not classified as a pixel', () => {
  const result = scan('<img src="https://cdn.vendor.net/open/logo.png" width="600" height="300">');
  assert.equal(result.suspicious.length, 0);
  assert.equal(result.externals.length, 1);
});

test('tracking-style link is classified separately from images', () => {
  const result = scan('<a href="https://links.vendor.net/redirect?utm_campaign=sale">Open</a>');
  assert.equal(result.suspicious.length, 0);
  assert.equal(result.links.length, 1);
  assert.equal(result.links[0].classification, 'tracking-link');
});


test('remote signature image with blocked zero layout stays external', () => {
  const result = scan('<img src="https://cdn.example.org/signatures/team-avatar.png" data-box-width="0" data-box-height="0">', 'example.org');
  assert.equal(result.suspicious.length, 0);
  assert.equal(result.externals.length, 1);
  assert.equal(result.externals[0].classification, 'external-image');
});
