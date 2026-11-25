/* VirusTotal Augment lookup for PixelGuard for Gmail. */
(() => {
  async function lookup(observable, apiKey, signal, request = globalThis.fetch) {
    const endpoint = new URL('https://www.virustotal.com/api/v3/widget/url');
    endpoint.searchParams.set('query', observable);
    const response = await request(endpoint.href, {
      method: 'GET', headers: { 'x-apikey': apiKey, accept: 'application/json' },
      credentials: 'omit', redirect: 'error', referrerPolicy: 'no-referrer', cache: 'no-store', signal
    });
    if (response.status === 404) return { ok: true, result: { status: 'no_report' } };
    if (!response.ok) {
      const errors = { 400: 'unavailable', 401: 'invalid_key', 403: 'forbidden', 429: 'rate_limit' };
      return { ok: false, error: errors[response.status] || 'network' };
    }
    let body;
    try { body = await response.json(); }
    catch (error) {
      if (error?.name === 'SyntaxError') return { ok: false, error: 'invalid_response' };
      throw error;
    }
    const reportUrl = globalThis.PixelGuardVTInventory.reportUrl(body?.data?.url);
    if (!reportUrl) return { ok: false, error: 'invalid_response' };
    const ratio = body.data.detection_ratio;
    const result = { status: 'reported' };
    if (Number.isInteger(ratio?.detections) && Number.isInteger(ratio?.total) &&
        ratio.detections >= 0 && ratio.total > 0 && ratio.detections <= ratio.total) {
      result.detections = ratio.detections;
      result.total = ratio.total;
    }
    return { ok: true, result, reportUrl };
  }
  globalThis.PixelGuardVTWidget = { lookup };
})();
