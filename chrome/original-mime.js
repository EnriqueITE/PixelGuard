// Extract the displayed HTML body as text. Nothing in the message is rendered.
(() => {
  const MAX_SOURCE = 8 * 1024 * 1024;
  const MAX_HTML = 2 * 1024 * 1024;

  function binaryString(bytes) {
    let result = '';
    for (let offset = 0; offset < bytes.length; offset += 16384) {
      result += String.fromCharCode(...bytes.subarray(offset, offset + 16384));
    }
    return result;
  }

  // MIME parameters may be quoted and contain semicolons or escaped quotes.
  function headerValue(value) {
    const type = value.split(';', 1)[0].trim().toLowerCase();
    const params = new Map();
    const parameter = /;[ \t]*([\w!#$%&'*+.^`|~-]+)[ \t]*=[ \t]*(?:"((?:\\.|[^"\\])*)"|([^;\s]*))/g;
    for (const match of value.matchAll(parameter)) {
      params.set(match[1].toLowerCase(), (match[2] ?? match[3]).replace(/\\(.)/g, '$1'));
    }
    return { type, params };
  }

  function entity(raw) {
    const end = raw.indexOf('\n\n');
    if (end < 0 || end > 128 * 1024) throw Error('Invalid MIME headers');
    const headers = new Map();
    const unfolded = raw.slice(0, end).replace(/\n[ \t]+/g, ' ');
    for (const line of unfolded.split('\n')) {
      const colon = line.indexOf(':');
      if (colon > 0) headers.set(line.slice(0, colon).toLowerCase(), line.slice(colon + 1).trim());
    }
    const content = headerValue(headers.get('content-type') || 'text/plain');
    const disposition = headerValue(headers.get('content-disposition') || '');
    // Extended and continued filenames (filename*, filename*0*, …) also mark attachments.
    const named = [...content.params.keys(), ...disposition.params.keys()].some(key => /^(?:file)?name(?:\*|$)/.test(key));
    return { content, headers, attached: named || disposition.type === 'attachment', body: raw.slice(end + 2) };
  }

  function childrenOf(part, budget) {
    const boundary = part.content.params.get('boundary');
    if (!boundary || boundary.length > 70 || /[^\x20-\x7e]/.test(boundary)) throw Error('Invalid MIME boundary');
    const escaped = boundary.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    const delimiter = new RegExp('^--' + escaped + '(--)?[ \\t]*(?:\\n|$)', 'gm');
    const children = [];
    let start = -1;
    for (const line of part.body.matchAll(delimiter)) {
      if (start >= 0) {
        if (++budget.parts > 256) throw Error('Too many MIME parts');
        // The LF immediately preceding the boundary belongs to the delimiter.
        const child = part.body.slice(start, line.index).replace(/\n$/, '');
        children.push(child.startsWith('\n') ? null : entity(child));
      }
      if (line[1]) return children;
      start = line.index + line[0].length;
    }
    throw Error('Incomplete MIME multipart');
  }

  function decode(part, sourceIsBytes) {
    const encoding = (part.headers.get('content-transfer-encoding') || '7bit').toLowerCase();
    let octets = part.body;
    if (encoding === 'base64') {
      octets = atob(octets);
    } else if (encoding === 'quoted-printable') {
      octets = octets.replace(/=(?:([\da-f]{2})|([ \t]*\n))?/gi, (_, hex, softBreak) => {
        if (hex) return String.fromCharCode(Number.parseInt(hex, 16));
        if (softBreak) return '';
        throw Error('Invalid quoted-printable body');
      });
    } else if (!['7bit', '8bit', 'binary'].includes(encoding)) {
      throw Error('Unsupported MIME encoding');
    }
    if (octets.length > MAX_HTML) throw Error('HTML body too large');
    // Text copied from Gmail's original-view page is already Unicode. Raw EML
    // bytes and ASCII transfer encodings still need the part's charset.
    if (!sourceIsBytes && encoding !== 'base64' && encoding !== 'quoted-printable') return octets;
    const bytes = Uint8Array.from(octets, character => character.charCodeAt(0));
    return new TextDecoder(part.content.params.get('charset') || 'utf-8').decode(bytes);
  }

  function html(raw) {
    const sourceIsBytes = raw instanceof Uint8Array;
    if (!(sourceIsBytes || typeof raw === 'string') || !raw.length || raw.length > MAX_SOURCE) {
      throw Error('Invalid original message size');
    }
    const source = (sourceIsBytes ? binaryString(raw) : raw).replace(/\r\n?/g, '\n');
    const budget = { parts: 1 };
    function select(part, depth) {
      if (depth > 16) throw Error('MIME nesting too deep');
      if (!part || part.attached) return null;
      const { type, params } = part.content;
      if (type === 'text/html') return decode(part, sourceIsBytes);
      if (!['multipart/mixed', 'multipart/related', 'multipart/alternative', 'multipart/signed'].includes(type)) return null;
      const children = childrenOf(part, budget);
      if (type === 'multipart/related') {
        const id = params.get('start');
        const root = id ? children.find(child => child?.headers.get('content-id') === id) : children[0];
        return select(root, depth + 1);
      }
      if (type === 'multipart/signed') return select(children[0], depth + 1);
      // In an alternative, the sender puts the preferred rendition last.
      if (type === 'multipart/alternative') children.reverse();
      for (const child of children) {
        const body = select(child, depth + 1);
        if (body?.trim()) return body;
      }
      return null;
    }
    const result = select(entity(source), 0);
    if (!result?.trim()) throw Error('Original has no HTML body');
    return result;
  }

  globalThis.PixelGuardOriginalMime = { html };
})();
