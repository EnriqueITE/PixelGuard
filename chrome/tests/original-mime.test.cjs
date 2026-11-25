const assert = require('node:assert/strict');
const test = require('node:test');
require('../original-mime.js');
const { html } = globalThis.PixelGuardOriginalMime;

const part = (headers, content) => headers + '\r\n\r\n' + content;
function multipart(subtype, boundary, children, extra = '') {
  const headers = 'Content-Type: multipart/' + subtype + ';\r\n boundary="' + boundary + '"' + extra;
  const sections = children.map(child => '--' + boundary + '\r\n' + child);
  return part(headers, ['preamble', ...sections, '--' + boundary + '--', 'epilogue'].join('\r\n'));
}

test('decodes the hidden remote image in the quoted-printable HTML body as text', () => {
  const encoded = '<img alt=3D"Ol=E9" style=3D"display:none" src=3D"https://mail.shop.app/_t/op=\r\nen/example">';
  const source = part('MIME-Version: 1.0\r\nContent-Type: text/html; charset=iso-8859-1\r\nContent-Transfer-Encoding: quoted-printable', encoded);
  assert.equal(html(source), '<img alt="Olé" style="display:none" src="https://mail.shop.app/_t/open/example">');
});

test('finds the preferred HTML alternative in mixed and related bodies, skipping files and forwarded mail', () => {
  const markup = '<p>Mensaje de prueba ☃</p>';
  const encoded = Buffer.from(markup).toString('base64').match(/.{1,16}/g).join('\r\n');
  const alternatives = multipart('alternative', 'al.t+1', [
    part('Content-Type: text/plain', 'Texto'),
    part('Content-Type: text/html', '<p>Old version</p>'),
    part('Content-Type: text/html; charset=utf-8\r\nContent-Transfer-Encoding: base64', encoded)
  ]);
  const related = multipart('related', 'related', [
    part('Content-Type: text/html\r\nContent-ID: <resource>', '<p>Auxiliary resource</p>'),
    'Content-ID: <body>\r\n' + alternatives
  ], '; start="<body>"');
  const source = multipart('mixed', 'mixed', [
    part("Content-Type: text/html; name*=utf-8''sample.html", 'Named attachment'),
    part('Content-Type: text/html\r\nContent-Disposition: attachment', 'Unnamed attachment'),
    part('Content-Type: message/rfc822', part('Content-Type: text/html', '<p>Attached email</p>')),
    related
  ]);
  assert.equal(html(source), markup);
});

test('distinguishes already-decoded Gmail text from undecoded EML bytes', () => {
  const markup = '<p>café</p>';
  const source = part('Content-Type: text/html; charset=windows-1252\r\nContent-Transfer-Encoding: 8bit', markup);
  assert.equal(html(source), markup);
  assert.equal(html(Buffer.from(source, 'latin1')), markup);
  assert.equal(html(Buffer.from(part('Content-Type: text/html; charset=UTF-8', '<p>☃</p>'))), '<p>☃</p>');
});

test('does not scan related resources, attachment filenames or forwarded mail for a missing body', () => {
  const markup = part('Content-Type: text/html', '<p>Other document</p>');
  const plain = part('Content-Type: text/plain', 'Body text');
  for (const source of [
    plain,
    multipart('related', 'r', [plain, markup]),
    multipart('related', 'r', [markup], '; start="<missing>"'),
    multipart('mixed', 'm', [plain, part('Content-Type: message/rfc822', markup)]),
    multipart('mixed', 'm', [plain, part("Content-Type: text/html\r\nContent-Disposition: inline; filename*0*=utf-8''file", 'Named attachment')])
  ]) assert.throws(() => html(source), /no HTML body/);
});

test('rejects truncated, undecodable and oversized originals', () => {
  assert.throws(() => html('<img>'));
  assert.throws(() => html(part('Content-Type: multipart/mixed; boundary=x', '--x\r\nContent-Type: text/html\r\n\r\ntest')), /Incomplete/);
  assert.throws(() => html(part('Content-Type: text/html\r\nContent-Transfer-Encoding: base64', '!!')));
  assert.throws(() => html(part('Content-Type: text/html\r\nContent-Transfer-Encoding: quoted-printable', '=ZZ')));
  assert.throws(() => html(part('Content-Type: text/html', 'x'.repeat(2 * 1024 * 1024 + 1))), /too large/);
  assert.throws(() => html('x'.repeat(8 * 1024 * 1024 + 1)), /size/);
});
