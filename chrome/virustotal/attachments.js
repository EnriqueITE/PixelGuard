/* Public VirusTotal v3 file reports and explicitly confirmed submissions. */
(() => {
  const origin = 'https://www.virustotal.com';
  const files = origin + '/api/v3/files';
  const maxSize = 50 * 1024 * 1024;
  const fail = error => ({ok: false, error});

  async function request(url, apiKey, signal, body) {
    return fetch(url, {
      method: body ? 'POST' : 'GET', body, signal,
      headers: {'x-apikey': apiKey, accept: 'application/json'},
      credentials: 'omit', redirect: 'error', referrerPolicy: 'no-referrer', cache: 'no-store'
    });
  }

  function unsuccessful(response) {
    const errors = {400: 'unavailable', 401: 'invalid_key', 403: 'forbidden', 413: 'too_large', 429: 'rate_limit'};
    return fail(errors[response.status] || 'network');
  }

  async function report(hash, apiKey, signal) {
    const response = await request(files + '/' + hash, apiKey, signal);
    if (!response.ok && response.status !== 404) return unsuccessful(response);
    const body = await response.json().catch(() => null);
    const queriedAt = Date.now();
    if (response.status === 404) {
      return body?.error?.code === 'NotFoundError' ?
        {ok: true, result: {status: 'no_report', queriedAt}} : fail('invalid_response');
    }
    const file = body?.data;
    if (file?.type !== 'file' || file.id !== hash) return fail('invalid_response');
    const result = {status: 'reported', queriedAt, reportUrl: origin + '/gui/file/' + hash};
    const stats = file.attributes?.last_analysis_stats;
    if (stats && ['malicious', 'suspicious', 'harmless', 'undetected'].every(
      key => Number.isSafeInteger(stats[key]) && stats[key] >= 0)) {
      const detections = stats.malicious + stats.suspicious;
      const total = detections + stats.harmless + stats.undetected;
      if (total > 0 && Number.isSafeInteger(total)) Object.assign(result, {detections, total});
    }
    return {ok: true, result};
  }

  function localBlobUrl(value, extensionRoot) {
    const prefix = 'blob:' + extensionRoot;
    return typeof value === 'string' && value.startsWith(prefix) &&
      /^[a-f\d]{8}-(?:[a-f\d]{4}-){3}[a-f\d]{12}$/i.test(value.slice(prefix.length));
  }

  function uploadDestination(value) {
    if (typeof value !== 'string') return null;
    let url;
    try { url = new URL(value); } catch { return null; }
    // The documented single-use URL can be returned with an http scheme.
    if (!['http:', 'https:'].includes(url.protocol) || url.hostname !== 'www.virustotal.com' ||
        url.port || url.username || url.password || url.hash || !url.pathname.startsWith('/_ah/upload/')) return null;
    url.protocol = 'https:';
    return url.href;
  }

  async function upload({hash, name, blobUrl}, apiKey, signal, charge) {
    const response = await fetch(blobUrl, {signal, credentials: 'omit', redirect: 'error'});
    if (!response.ok) return fail('unavailable');
    if (Number(response.headers.get('content-length')) > maxSize) return fail('too_large');
    const file = await response.blob();
    if (file.size > maxSize) return fail('too_large');
    const digest = await crypto.subtle.digest('SHA-256', await file.arrayBuffer());
    const actual = Array.from(new Uint8Array(digest), byte => byte.toString(16).padStart(2, '0')).join('');
    if (actual !== hash) return fail('report_expired');

    let destination = files;
    if (file.size > 32 * 1024 * 1024) {
      const limit = await charge();
      if (limit) return limit;
      const allocation = await request(files + '/upload_url', apiKey, signal);
      if (!allocation.ok) return unsuccessful(allocation);
      const body = await allocation.json().catch(() => null);
      destination = uploadDestination(body?.data);
      if (!destination) return fail('invalid_response');
    }
    const limit = await charge();
    if (limit) return limit;
    const form = new FormData();
    form.append('file', file, name);
    const submission = await request(destination, apiKey, signal, form);
    if (!submission.ok) return unsuccessful(submission);
    const body = await submission.json().catch(() => null);
    const id = body?.data?.id;
    if (body?.data?.type !== 'analysis' || typeof id !== 'string' || !/^[A-Za-z0-9_+=/-]{1,512}$/.test(id)) {
      return fail('invalid_response');
    }
    return {ok: true, analysisId: id};
  }

  globalThis.PixelGuardVTAttachments = {report, localBlobUrl, upload};
})();
