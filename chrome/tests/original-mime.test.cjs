const assert = require('node:assert/strict');
const test = require('node:test');
require('../original-mime.js');
const { html, attachment } = globalThis.PixelGuardOriginalMime;

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

test('recognizes a plain-text original without treating attachments or malformed data as the message body', () => {
  const plain = part('From: sender@example.test', 'See https://example.test');
  assert.throws(() => html(plain), { name: 'PlainTextOriginal' });
  const attached = part('Content-Type: text/plain\r\nContent-Disposition: attachment', 'Attached text');
  assert.throws(() => html(multipart('mixed', 'm', [attached])), { name: 'Error' });
  assert.throws(() => html('invalid headers\n\nresponse'), { name: 'Error' });
});

test('selects the exact MIME part for duplicate filenames and skips attached messages', () => {
  const named = (name, bytes) => part('Content-Type: application/octet-stream\r\nContent-Disposition: attachment; filename="' +
    name + '"\r\nContent-Transfer-Encoding: base64', Buffer.from(bytes).toString('base64'));
  const source = multipart('mixed', 'b', [part('Content-Type: text/plain', 'Hi'), named('same.bin', [0, 1]),
    named('same.bin', [255, 0, 128]), part('Content-Type: message/rfc822', named('inner.bin', [9]))]);
  assert.deepEqual([...attachment(source, {name: 'same.bin', partId: '0.2'}, 3)], [255, 0, 128]);
  assert.throws(() => attachment(source, {name: 'same.bin'}, 3), /unavailable/);
  assert.throws(() => attachment(source, {name: 'inner.bin', partId: '0.3'}, 3), /unavailable/);
  assert.throws(() => attachment(source, {name: 'same.bin', partId: '0.2'}, 2), /too large/);
  const continued = part('Content-Type: application/octet-stream\r\nContent-Disposition: attachment;' +
    ' filename*0="sa"; filename*1="me.bin"\r\nContent-Transfer-Encoding: base64', 'Aw==');
  const mixed = multipart('mixed', 'b', [part('Content-Type: text/plain', 'Hi'), named('same.bin', [2]), continued]);
  assert.deepEqual([...attachment(mixed, {name: 'same.bin', partId: '0.2'}, 9)], [3]);
  assert.throws(() => attachment(mixed, {name: 'same.bin', partId: '0.8'}, 9), /unavailable/);
  const unique = multipart('mixed', 'b', [part('Content-Type: text/plain', 'Hi'), named('only.bin', [2]), continued]);
  assert.throws(() => attachment(unique, {name: 'only.bin', partId: '0.2'}, 9), /unavailable/);
});

test('preserves binary line endings, zero bytes and encoded international filenames from the original', () => {
  const bytes = '\x00\xff\r\nx\r\n';
  const binary = part("Content-Type: application/octet-stream\r\nContent-Disposition: attachment; filename*0*=utf-8''caf%C3%A9;" +
    "\r\n filename*1*=.bin\r\nContent-Transfer-Encoding: binary", bytes);
  const quoted = part('Content-Type: application/octet-stream\r\nContent-Disposition: attachment; filename="=?UTF-8?B?Y2Fmw6kudHh0?="\r\n' +
    'Content-Transfer-Encoding: quoted-printable', '=FF=00=\r\n=01\r\nend');
  const source = multipart('mixed', 'mix', [binary, quoted]);
  const pick = (raw, name) => Buffer.from(attachment(raw, {name}, 50));
  assert.deepEqual(pick(Buffer.from(source, 'latin1'), 'café.bin'), Buffer.from(bytes, 'latin1'));
  assert.deepEqual(pick(Buffer.from(source, 'latin1'), 'café.txt'), Buffer.from('\xff\x00\x01\r\nend', 'latin1'));
  assert.throws(() => pick(source.replaceAll('\r\n', '\n'), 'café.bin'), /Original bytes/);
  assert.throws(() => pick(source.replaceAll('\r\n', '\n'), 'café.txt'), /Original bytes/);
  assert.throws(() => attachment(source, {name: 'café.bin', duplicateName: true}, 50), /unavailable/);
});
