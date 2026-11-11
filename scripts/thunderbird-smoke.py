"""Isolated Thunderbird runtime probe. Never opens an existing user profile.

Requires Mozilla's marionette_driver in dist/qa-tools/python or the environment.
Uses a test-only driver bridge and a public-API helper with synthetic messages.
This script and all QA profiles are excluded from the release XPI.
"""
import argparse
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import time
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import zipfile


def main():
    root = Path(__file__).resolve().parent.parent
    parser = argparse.ArgumentParser()
    parser.add_argument('--binary', required=True)
    parser.add_argument('--label', default='installed')
    parser.add_argument('--addon', type=Path, help='Exact XPI to install; defaults to source directory')
    parser.add_argument('--helper', action='store_true', help='Run public-API helper with synthetic messages')
    args = parser.parse_args()
    sys.path.insert(0, str(root / 'dist' / 'qa-tools' / 'python'))
    from marionette_driver.marionette import Marionette
    from marionette_driver.addons import Addons

    stamp = time.strftime('%Y%m%d-%H%M%S')
    run = root / 'dist' / 'runtime-qa' / f'{args.label}-{stamp}'
    profile = run / 'profile'
    profile.mkdir(parents=True, exist_ok=False)
    # Reserve an unused loopback port. Existing Thunderbird instances are neither
    # inspected nor reused, and no personal mail accounts are configured.
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        port = sock.getsockname()[1]
    prefs = {
        'marionette.port': port,
        'mail.provider.suppress_dialog_on_startup': True,
        'mail.shell.checkDefaultClient': False,
        'mailnews.start_page.enabled': False,
        'app.update.auto': False,
        'app.update.enabled': False,
        'extensions.update.enabled': False,
        'extensions.getAddons.cache.enabled': False,
        'extensions.blocklist.enabled': False,
        'datareporting.healthreport.uploadEnabled': False,
        'datareporting.policy.dataSubmissionEnabled': False,
        'toolkit.telemetry.enabled': False,
        'mailnews.message_display.disable_remote_image': True,
        'network.proxy.type': 1,
        'network.proxy.http': '127.0.0.1',
        'network.proxy.http_port': 9,
        'network.proxy.ssl': '127.0.0.1',
        'network.proxy.ssl_port': 9,
        'network.proxy.no_proxies_on': '127.0.0.1,localhost',
        'browser.dom.window.dump.enabled': True,
    }
    (profile / 'user.js').write_text(''.join(
        f'user_pref({json.dumps(k)}, {json.dumps(v)});\n' for k, v in prefs.items()), encoding='utf-8')
    env = os.environ.copy()
    env['MOZ_REMOTE_ALLOW_SYSTEM_ACCESS'] = '1'
    env['MOZ_HEADLESS'] = '1'
    startup = subprocess.STARTUPINFO() if os.name == 'nt' else None
    if startup:
        startup.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        startup.wShowWindow = subprocess.SW_HIDE
    result = {'binary': args.binary, 'profile': str(profile), 'checks': []}
    payload = {}
    received = threading.Event()
    class Sink(BaseHTTPRequestHandler):
        def do_POST(self):
            if self.path == '/result':
                payload.update(json.loads(self.rfile.read(int(self.headers['Content-Length']))))
                received.set()
            self.send_response(200)
            self.end_headers()
        def do_GET(self):
            payload.setdefault('resourceRequests', []).append(self.path)
            self.send_response(200)
            self.end_headers()
        def log_message(self, *_args):
            pass
    server = ThreadingHTTPServer(('127.0.0.1', 0), Sink)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    client = None
    with (run / 'thunderbird.log').open('wb') as log:
        proc = subprocess.Popen([
            args.binary, '-no-remote', '-profile', str(profile),
            '--marionette', '--allow-system-access', '-headless'],
            env=env, stdout=log, stderr=log, startupinfo=startup)
        try:
            client = Marionette(host='127.0.0.1', port=port, socket_timeout=60)
            client.raise_for_port(timeout=40)
            client.start_session({'pageLoadStrategy': 'none'})
            client.set_context('chrome')
            client.timeout.script = 60
            result['version'] = client.execute_script('return Services.appinfo.version;')
            addon = args.addon.resolve() if args.addon else root
            result['artifact'] = str(addon)
            if addon.is_file():
                import hashlib
                result['artifactSha256'] = hashlib.sha256(addon.read_bytes()).hexdigest()
            result['addonId'] = Addons(client).install(str(addon), temp=True)
            result['checks'].append({'name': 'temporary_addon_install', 'passed': True})
            result['initialPermissions'] = client.execute_async_script("""
              const done = arguments[arguments.length-1];
              (async () => {
                const { ExtensionParent } = ChromeUtils.importESModule('resource://gre/modules/ExtensionParent.sys.mjs');
                const extension = ExtensionParent.GlobalManager.getExtension('pixel-guard@enriqueite.com');
                const context = Array.from(extension.views).find(v => v.viewType === 'background');
                const getAll = await context.apiCan.asyncFindAPIPath('permissions.getAll');
                return getAll();
              })().then(done,error=>done({error:String(error)}));
            """)
            if args.helper:
                helper = run / 'helper'
                helper.mkdir()
                helper_manifest = {'manifest_version': 2, 'name': 'PixelGuard isolated QA helper', 'version': '1.0',
                    'browser_specific_settings': {'gecko': {'id': 'pixelguard-qa@example.invalid', 'strict_min_version': '115.0'}},
                    'permissions': ['messagesRead', 'http://127.0.0.1/*'],
                    'background': {'scripts': ['config.js', 'inventory.js', 'helper.js']}}
                (helper / 'manifest.json').write_text(json.dumps(helper_manifest),encoding='utf-8')
                if addon.is_file():
                    with zipfile.ZipFile(addon) as archive:
                        inventory = archive.read('virustotal/inventory.js')
                else:
                    inventory = (root / 'virustotal' / 'inventory.js').read_bytes()
                (helper / 'inventory.js').write_bytes(inventory)
                (helper / 'helper.js').write_bytes((root / 'scripts' / 'thunderbird-helper.js').read_bytes())
                endpoint = f'http://127.0.0.1:{server.server_port}'
                (helper / 'config.js').write_text('const QA_ENDPOINT = '+json.dumps(endpoint)+';\n',encoding='utf-8')
                Addons(client).install(str(helper),temp=True)
                if not received.wait(45):
                    raise RuntimeError('QA helper did not return a result within 45 seconds')
                result['helper'] = payload
                result['helper']['resourceRequests'] = payload.get('resourceRequests', [])
                result['checks'].append({'name': 'no_parser_or_message_resource_fetch', 'passed': not payload.get('resourceRequests')})
                message_tab = next((check.get('detail', {}).get('tabId')
                                    for check in payload.get('checks', [])
                                    if check['name'] == 'open_message_tab' and check['passed']), None)
                if message_tab is None:
                    raise RuntimeError('QA helper did not leave a normal message tab to inspect')
                # Read the production extension's isolated world. Do not inject the
                # scanner here: the check must fail when registration was rejected.
                for attempt in range(12):
                    result['messageScript'] = client.execute_async_script("""
                      const tabId = arguments[0];
                      const done = arguments[arguments.length-1];
                      (async () => {
                        const { ExtensionParent } = ChromeUtils.importESModule('resource://gre/modules/ExtensionParent.sys.mjs');
                        const extension = ExtensionParent.GlobalManager.getExtension('pixel-guard@enriqueite.com');
                        const context = Array.from(extension.views).find(v => v.viewType === 'background');
                        const execute = await context.apiCan.asyncFindAPIPath('tabs.executeScript');
                        // This test-only bridge calls the implementation after
                        // schema normalization: include the standard defaults.
                        return execute(tabId, {file: null, frameId: null, allFrames: false,
                          matchAboutBlank: false, runAt: 'document_idle', code: `(() => {
                          const banners = document.querySelectorAll('.pixelguard-banner');
                          const banner = banners[0];
                          return {
                            initialized: globalThis.PixelGuardScanDocument === document,
                            scannerAvailable: typeof globalThis.PixelGuardScanner?.scanDocument === 'function',
                            bannerCount: banners.length,
                            bannerVisible: !!banner && banner.getBoundingClientRect().height > 0 &&
                              getComputedStyle(banner).display !== 'none' && getComputedStyle(banner).visibility !== 'hidden'
                          };
                        })()`});
                      })().then(done, error => done({error:String(error), message:error?.message, detail:JSON.stringify(error)}));
                    """, script_args=[message_tab])
                    observations = result['messageScript']
                    if isinstance(observations, list) and any(
                            observation.get('initialized') and observation.get('scannerAvailable') and
                            observation.get('bannerCount') == 1 and observation.get('bannerVisible')
                            for observation in observations):
                        break
                    if attempt < 11:
                        time.sleep(0.3)
                observations = result['messageScript']
                result['checks'].append({
                    'name': 'production_message_script_and_visible_banner',
                    'passed': isinstance(observations, list) and any(
                        observation.get('initialized') and observation.get('scannerAvailable') and
                        observation.get('bannerCount') == 1 and observation.get('bannerVisible')
                        for observation in observations)
                })
                result['optionsTab'] = client.execute_async_script("""
                  const done = arguments[arguments.length-1];
                  (async () => {
                    const { ExtensionParent } = ChromeUtils.importESModule('resource://gre/modules/ExtensionParent.sys.mjs');
                    const extension = ExtensionParent.GlobalManager.getExtension('pixel-guard@enriqueite.com');
                    const context = Array.from(extension.views).find(v => v.viewType === 'background');
                    const create = await context.apiCan.asyncFindAPIPath('tabs.create');
                    return create({url:extension.baseURI.spec+'options/options.html',active:true});
                  })().then(done, error => done({error:String(error)}));
                """)
                try:
                    time.sleep(1)
                    image = client.screenshot(format='binary')
                    (run / 'options.png').write_bytes(image)
                    result['screenshot'] = str(run / 'options.png')
                except Exception as exc:
                    result['screenshotError'] = str(exc)
        except Exception as exc:
            result['error'] = f'{type(exc).__name__}: {exc}'
        finally:
            if client:
                try:
                    client.set_context('chrome')
                    client.execute_script('Services.startup.quit(Ci.nsIAppStartup.eForceQuit);')
                except Exception:
                    pass
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.terminate()
                proc.wait(timeout=10)
    (run / 'result.json').write_text(json.dumps(result, indent=2), encoding='utf-8')
    server.shutdown()
    print(json.dumps(result, indent=2))
    print(f'Result: {run / "result.json"}')
    failed = ('error' in result or result.get('helper', {}).get('error') or
              result.get('optionsTab', {}).get('error') or
              any(not c['passed'] for c in result['checks']))
    return 1 if failed else 0


if __name__ == '__main__':
    raise SystemExit(main())
