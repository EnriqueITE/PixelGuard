// Extract displayable message bodies as data. Nothing in the message is rendered.
(() => {
  const MAX_SOURCE = 8 * 1024 * 1024;
  const MAX_BODY_BYTES = 2 * 1024 * 1024;

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
    const separator = /\r?\n\r?\n/.exec(raw);
    if (!separator || separator.index > 128 * 1024) throw Error('Invalid MIME headers');
    const headers = new Map();
    const unfolded = raw.slice(0, separator.index).replace(/\r?\n[ \t]+/g, ' ');
    for (const line of unfolded.split(/\r?\n/)) {
      const colon = line.indexOf(':');
      if (colon > 0) headers.set(line.slice(0, colon).toLowerCase(), line.slice(colon + 1).trim());
    }
    const content = headerValue(headers.get('content-type') || 'text/plain');
    const disposition = headerValue(headers.get('content-disposition') || '');
    // Extended and continued filenames (filename*, filename*0*, …) also mark attachments.
    const named = [...content.params.keys(), ...disposition.params.keys()].some(key => /^(?:file)?name(?:\*|$)/.test(key));
    return { content, disposition, headers, attached: named || disposition.type === 'attachment',
      body: raw.slice(separator.index + separator[0].length) };
  }

  function* childrenOf(part, budget, parseChild = raw => /^\r?\n/.test(raw) ? null : entity(raw)) {
    const boundary = part.content.params.get('boundary');
    if (!boundary || boundary.length > 70 || /[^\x20-\x7e]/.test(boundary)) throw Error('Invalid MIME boundary');
    const escaped = boundary.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    const delimiter = new RegExp('^--' + escaped + '(--)?[ \\t]*(?:\\r?\\n|$)', 'gm');
    let start = -1;
    for (const line of part.body.matchAll(delimiter)) {
      if (start >= 0) {
        if (++budget.parts > 256) throw Error('Too many MIME parts');
        // The line break immediately preceding the boundary belongs to the delimiter.
        const child = part.body.slice(start, line.index).replace(/\r?\n$/, '');
        yield parseChild(child);
      }
      if (line[1]) return;
      start = line.index + line[0].length;
    }
    throw Error('Incomplete MIME multipart');
  }

  function decode(part, sourceIsBytes, budget) {
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
    if (octets.length > budget.remaining) throw Error('Message bodies too large');
    // Text copied from Gmail's original-view page is already Unicode. Raw EML
    // bytes and ASCII transfer encodings still need the part's charset.
    let text = octets;
    if (sourceIsBytes || encoding === 'base64' || encoding === 'quoted-printable') {
      const bytes = Uint8Array.from(octets, character => character.charCodeAt(0));
      text = new TextDecoder(part.content.params.get('charset') || 'utf-8').decode(bytes);
    }
    budget.remaining -= octets.length;
    return text;
  }

  function bodyParts(raw) {
    const sourceIsBytes = raw instanceof Uint8Array;
    if (!(sourceIsBytes || typeof raw === 'string') || !raw.length || raw.length > MAX_SOURCE) {
      throw Error('Invalid original message size');
    }
    const source = (sourceIsBytes ? binaryString(raw) : raw).replace(/\r\n?/g, '\n');
    const budget = { parts: 1, remaining: MAX_BODY_BYTES };
    const parts = [];
    let unreadable;
    function parseChild(rawChild) {
      // A MIME child without any headers has the default text/plain type.
      try {
        const child = entity(rawChild.startsWith('\n') ? 'Content-Type: text/plain\n' + rawChild : rawChild);
        return child.headers.size ? child : null;
      } catch { return null; }
    }
    function select(part, depth) {
      try {
        if (!part) throw Error('Missing MIME body');
        if (part.attached || part.content.type === 'message/rfc822') return;
        if (depth > 16) throw Error('MIME nesting too deep');
        const {type, params} = part.content;
        if (type === 'text/plain' || type === 'text/html') {
          parts.push({type, content: decode(part, sourceIsBytes, budget)});
          return;
        }
        if (!['multipart/mixed', 'multipart/related', 'multipart/alternative', 'multipart/signed'].includes(type)) {
          if (/^(?:multipart\/|text\/|message\/|application\/(?:xhtml\+xml|(?:x-)?pkcs7-mime)$)/.test(type)) {
            throw Error('Unsupported message body');
          }
          return;
        }
        const childParts = childrenOf(part, budget, parseChild);
        if (type === 'multipart/mixed') {
          // Every inline sibling is relevant. Keep each one as soon as its
          // closing boundary is known, even if a later child exceeds a limit.
          for (const child of childParts) select(child, depth + 1);
          return;
        }
        // A rendition or related root must be selected from the proper group.
        // Withhold that selection if the group could not be read to its end.
        const children = [...childParts];
        if (type === 'multipart/related') {
          const id = params.get('start');
          select(id ? children.find(child => child?.headers.get('content-id') === id) : children[0], depth + 1);
        } else if (type === 'multipart/signed') {
          select(children[0], depth + 1);
        } else {
          // Use a single readable rendition, preferring the last supported one.
          const before = parts.length;
          for (let i = children.length - 1; i >= 0; i--) {
            select(children[i], depth + 1);
            if (parts.slice(before).some(item => item.content.trim())) break;
            if (i > 0) parts.length = before;
          }
        }
      } catch (error) {
        // Retain readable mixed siblings and carry the gap through to the UI.
        unreadable ??= error;
      }
    }
    const root = entity(source);
    if (!root.headers.size) throw Error('Invalid MIME headers');
    select(root, 0);
    if (!parts.length) throw unreadable || Error('Original has no displayable text body');
    return {parts, partial: !!unreadable};
  }

  function mimeName(params, key, sourceIsBytes) {
    let extended = params.get(key + '*');
    let name = params.get(key) || '';
    if (!extended && params.has(key + '*0*')) {
      extended = '';
      for (let i = 0; ; i++) {
        const encoded = params.get(key + '*' + i + '*');
        const value = encoded ?? params.get(key + '*' + i);
        if (value === undefined) break;
        extended += encoded === undefined ? value.replace(/%/g, '%25') : value;
      }
    } else if (!extended && params.has(key + '*0')) {
      name = '';
      for (let i = 0; params.has(key + '*' + i); i++) name += params.get(key + '*' + i);
    }
    if (extended) {
      const match = /^([^']*)'[^']*'(.*)$/.exec(extended);
      if (match) try {
        const bytes = match[2].replace(/%([\da-f]{2})/gi, (_, hex) => String.fromCharCode(parseInt(hex, 16)));
        return new TextDecoder(match[1] || 'utf-8', {fatal: true}).decode(Uint8Array.from(bytes, c => c.charCodeAt(0)));
      } catch { /* Fall back to the ordinary name, if present. */ }
    }
    if (sourceIsBytes && /[^\x00-\x7f]/.test(name)) {
      try { name = new TextDecoder('utf-8', {fatal: true}).decode(Uint8Array.from(name, c => c.charCodeAt(0))); } catch {}
    }
    return name.replace(/(\?=)[ \t]+(?==\?)/g, '$1').replace(/=\?([^?\s]+)\?([bq])\?([^?]*)\?=/gi,
      (word, charset, encoding, value) => {
        try {
          const bytes = encoding.toLowerCase() === 'b' ? atob(value) :
            value.replace(/_/g, ' ').replace(/=([\da-f]{2})/gi, (_, hex) => String.fromCharCode(parseInt(hex, 16)));
          return new TextDecoder(charset, {fatal: true}).decode(Uint8Array.from(bytes, c => c.charCodeAt(0)));
        } catch { return word; }
      });
  }

  function attachment(raw, {name, partId, duplicateName}, limit) {
    const sourceIsBytes = raw instanceof Uint8Array;
    const source = sourceIsBytes ? binaryString(raw) : raw;
    const matches = [];
    const budget = {parts: 1};
    function visit(part, path, depth) {
      if (!part) return;
      if (depth > 16) throw Error('MIME nesting too deep');
      const filename = mimeName(part.disposition.params, 'filename', sourceIsBytes) ||
        mimeName(part.content.params, 'name', sourceIsBytes);
      if (part.attached || part.content.type === 'message/rfc822') {
        if (filename === name) matches.push({part, path});
        return;
      }
      if (part.content.type.startsWith('multipart/')) {
        let index = 0;
        for (const child of childrenOf(part, budget)) visit(child, path + '.' + index++, depth + 1);
      }
    }
    visit(entity(source), '0', 0);
    // Gmail's part identifier disambiguates identically named attachments.
    const selected = partId ? matches.find(item => item.path === partId) : !duplicateName && matches.length === 1 && matches[0];
    if (!selected) throw Error('Gmail attachment unavailable');
    const encoding = (selected.part.headers.get('content-transfer-encoding') || '7bit').toLowerCase();
    let bytes = selected.part.body;
    if (encoding === 'base64') {
      bytes = bytes.replace(/[ \t\r\n]/g, '');
      if (bytes.length > Math.ceil(limit / 3) * 4) throw new RangeError('Attachment too large');
      bytes = atob(bytes);
    } else {
      if (encoding === 'quoted-printable') {
        bytes = bytes.replace(/=[ \t]*\r?\n/g, '');
      } else if (!['binary', '7bit', '8bit'].includes(encoding)) throw Error('Unsupported attachment encoding');
      // Gmail's HTML source view normalizes newlines and decodes text as Unicode.
      // Only ASCII without hard newlines or transfer-encoded octets survive it exactly.
      if (!sourceIsBytes && /[^\x20-\x7e\t]/.test(bytes)) throw Error('Original bytes required');
      if (encoding === 'quoted-printable') bytes = bytes.replace(/=(?:([\da-f]{2}))?/gi, (_, hex) => {
        if (!hex) throw Error('Invalid quoted-printable attachment');
        return String.fromCharCode(parseInt(hex, 16));
      });
    }
    if (bytes.length > limit) throw new RangeError('Attachment too large');
    const result = new Uint8Array(bytes.length);
    for (let i = 0; i < bytes.length; i++) result[i] = bytes.charCodeAt(i);
    return result;
  }

  globalThis.PixelGuardOriginalMime = { bodyParts, attachment };
})();
