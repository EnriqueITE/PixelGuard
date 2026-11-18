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


def observe_message(client, tab_id):
    """Inspect the production script's world; never inject the detector or its CSS."""
    observation = production_tab_script(client, tab_id, """(async () => {
      const banners = document.querySelectorAll('.pixelguard-banner');
      const banner = banners[0];
      const style = banner && getComputedStyle(banner);
      const rect = banner?.getBoundingClientRect();
      const scroll = document.scrollingElement;
      const initial = scroll.scrollTop;
      scroll.scrollTop = 500;
      const scrolled = scroll.scrollTop - initial;
      const scrolledBottom = banner?.getBoundingClientRect().bottom;
      scroll.scrollTop = initial;
      const response = await browser.runtime.sendMessage({type:'pg:getFindings', tabId: TAB_ID});
      const f = response?.findings;
      return {initialized:globalThis.PixelGuardScanDocument === document,
        scanner:typeof globalThis.PixelGuardScanner?.scanDocument === 'function',
        banners:banners.length, height:rect?.height || 0, top:rect?.top, position:style?.position,
        color:style?.backgroundColor, scrolled, scrolledBottom, viewportWidth:innerWidth,
        viewportHeight:innerHeight, suspicious:f?.suspicious?.length, external:f?.externals?.length,
        links:f?.links?.length};
    })()""".replace('TAB_ID', str(tab_id)))
    observation['badge'] = client.execute_async_script("""
      const [tabId, done] = arguments;
      (async () => {
        const { ExtensionParent } = ChromeUtils.importESModule('resource://gre/modules/ExtensionParent.sys.mjs');
        const ext = ExtensionParent.GlobalManager.getExtension('pixel-guard@enriqueite.com');
        const bg = Array.from(ext.views).find(v => v.viewType === 'background');
        const get = await bg.apiCan.asyncFindAPIPath('browserAction.getBadgeText');
        return get({tabId});
      })().then(done, e => done({error:String(e)}));
    """, script_args=[tab_id])
    return observation


def production_tab_script(client, tab_id, code):
    observations = client.execute_async_script("""
      const [tabId, code, done] = arguments;
      (async () => {
        const { ExtensionParent } = ChromeUtils.importESModule('resource://gre/modules/ExtensionParent.sys.mjs');
        const extension = ExtensionParent.GlobalManager.getExtension('pixel-guard@enriqueite.com');
        const context = Array.from(extension.views).find(v => v.viewType === 'background');
        const execute = await context.apiCan.asyncFindAPIPath('tabs.executeScript');
        // This test bridge calls the implementation after schema normalization.
        return execute(tabId, {file:null, frameId:null, allFrames:false,
          matchAboutBlank:false, runAt:'document_idle', code});
      })().then(done, error => done({error:String(error)}));
    """, script_args=[tab_id, code])
    if not isinstance(observations, list) or not observations:
        raise RuntimeError(f'Production document probe failed: {observations}')
    return observations[0]


def check_banner_behavior(client, result, tabs, mode):
    result['bannerProbe'] = {}
    modes = [('default', False)] if mode != 'fixed' else [('default', False), ('enabled', True), ('disabled', False)]
    for phase, enabled in modes:
        if phase != 'default':
            ack = production_tab_script(client, tabs['tracking'],
                "browser.runtime.sendMessage({type:'pg:setInlineBanner',value:" +
                ('true' if enabled else 'false') + "})")
            if not ack or not ack.get('ok'):
                raise RuntimeError(f'Inline banner setting rejected: {ack}')
        # Initial message/context hooks and throttled rescans must complete before
        # asserting absence. Older builds scheduled a last scan at 1800 ms.
        time.sleep(2.5)
        observations = {}
        for name, tab_id in tabs.items():
            obs = observe_message(client, tab_id)
            observations[name] = obs
            if mode == 'compare':
                continue   # Historical releases are observations, not expectations.
            tracking = name != 'ordinary'
            passed = obs.get('initialized') and obs.get('scanner')
            passed = passed and ((obs.get('suspicious') or 0) > 0 if tracking else
                                 obs.get('suspicious') == 0 and (obs.get('external') or 0) > 0)
            expected_badge = ''.join(str(obs[key]) for key in ('suspicious', 'external', 'links'))
            passed = passed and obs['badge'] == expected_badge
            if enabled and tracking:
                passed = passed and obs['banners'] == 1 and 0 < obs['height'] <= 48
                passed = passed and obs['position'] not in ('fixed', 'sticky')
                passed = passed and obs['scrolled'] > obs['height'] and obs['scrolledBottom'] <= 0
            else:
                passed = passed and obs['banners'] == 0
            result['checks'].append({'name': f'{phase}_{name}_analysis_and_banner', 'passed': bool(passed)})
        result['bannerProbe'][phase] = observations


def open_widget_pages(client, message_tab_id):
    """Keep the real message active while opening the packaged popup and options in background tabs."""
    pages = client.execute_async_script("""
      const [messageId, done] = arguments;
      (async () => {
        const { ExtensionParent } = ChromeUtils.importESModule('resource://gre/modules/ExtensionParent.sys.mjs');
        const ext = ExtensionParent.GlobalManager.getExtension('pixel-guard@enriqueite.com');
        const bg = Array.from(ext.views).find(v => v.viewType === 'background');
        const api = path => bg.apiCan.asyncFindAPIPath(path);
        const update = await api('tabs.update');
        const tab = await update(messageId, {active:true});
        Services.wm.getMostRecentWindow('mail:3pane').focus();
        const create = await api('tabs.create');
        const page = path => create({url:ext.baseURI.resolve(path), windowId:tab.windowId, active:false});
        const options = await page('options/options.html');
        const popup = await page('popup/popup.html');
        return {options:options.id, popup:popup.id};
      })().then(done, error => done({error:String(error)}));
    """, script_args=[message_tab_id])
    if pages.get('error'):
        raise RuntimeError(pages['error'])
    return pages


def widget_page_script(client, tab_id, script, args=()):
    # Marionette addresses the extension page's own browsing context. Keeping tabs
    # inactive lets the unmodified popup resolve the real active message normally.
    reply = client.execute_async_script("""
      const [tabId, script, args, done] = arguments;
      (async () => {
        const { ExtensionParent } = ChromeUtils.importESModule('resource://gre/modules/ExtensionParent.sys.mjs');
        const ext = ExtensionParent.GlobalManager.getExtension('pixel-guard@enriqueite.com');
        const frame = ext.tabManager.get(tabId).browser;
        if (frame.currentURI.spec === 'about:blank' || !frame.browsingContext.currentWindowGlobal) return {};
        if (!frame.currentURI.spec.startsWith(ext.baseURI.spec)) throw Error('Expected a PixelGuard page');
        const actor = frame.browsingContext.currentWindowGlobal.getActor('MarionetteCommands');
        return actor.executeScript(script, args, {timeout:5000, sandboxName:'pixelguard-qa', newSandbox:true});
      })().then(done, error => done({error:String(error)}));
    """, script_args=[tab_id, script, list(args)])
    if isinstance(reply, dict) and reply.get('error'):
        raise RuntimeError(reply['error'])
    return reply


def check_widget_languages(client, result, message_tab_id, clean_tab_id, addon, run):
    pages = open_widget_pages(client, message_tab_id)
    options_text = """
        const text = id => document.querySelector(id)?.textContent;
        const picker = document.querySelector('#uiLanguage');
        return {lang:document.documentElement?.lang, selection:picker?.value,
          ready:!!picker && !picker.disabled, options_title:text('h1'),
          options_languageAuto:text('#uiLanguage option[value="auto"]')};
    """
    popup_text = """
        const text = id => document.querySelector(id)?.textContent;
        const vt = document.querySelector('#vtSection');
        if (document.readyState === 'complete' && vt && !vt.open) vt.querySelector('summary').click();
        return {lang:document.documentElement?.lang, popup_thisMessage:text('h3'),
          alert:text('.chip-s [data-i18n]'), image:text('.chip-e [data-i18n]'), link:text('.chip-l [data-i18n]'),
          counts:['#sumS','#sumE','#sumL'].map(text),
          ui_openOptions:text('#openOptions'), ui_buyCoffee:text('[data-i18n="ui_buyCoffee"]'),
          popup_summary:text('[data-i18n="popup_summary"]'), popup_senderDomain:text('[data-i18n="popup_senderDomain"]'),
          popup_noDetails:text('.empty-details') ?? null, reason_onePixel:text('.suspicious .finding-reason') ?? null,
          popup_confidence_medium:text('.suspicious .confidence') ?? null, popup_copy:text('.suspicious .copy-btn') ?? null,
          vt_title:text('.vt-summary-title'), vt_setup:text('#vtSetup'), vt_disabled:text('#vtStatus')};
    """

    def read_catalog(locale, automatic):
        # Automatic mode can report a regional UI language (e.g. fr-FR).
        tags = (locale, locale.split('_')[0], 'en') if automatic else (locale,)
        candidates = [f'_locales/{tag}/messages.json' for tag in tags]
        if addon.is_file():
            with zipfile.ZipFile(addon) as archive:
                name = next(name for name in candidates if name in archive.namelist())
                return json.loads(archive.read(name))
        path = next(addon / name for name in candidates if (addon / name).is_file())
        return json.loads(path.read_text(encoding='utf-8'))

    def wait_text(tab_id, script, expected):
        deadline = time.monotonic() + 5
        while True:
            found = widget_page_script(client, tab_id, script)
            if all(found.get(key) == value for key, value in expected.items()) or time.monotonic() >= deadline:
                return found
            time.sleep(0.15)

    initial = wait_text(pages['options'], options_text, {'selection': 'auto', 'ready': True})
    auto_locale = initial['lang'].replace('-', '_')
    # The popup reads the active message on opening. Keep both packaged views
    # alive to verify changes against real empty and populated findings.
    initial_catalog = read_catalog(auto_locale, True)
    wait_text(pages['popup'], popup_text, {'reason_onePixel': initial_catalog['reason_onePixel']['message'],
                                          'vt_disabled': initial_catalog['vt_disabled']['message']})
    clean_pages = open_widget_pages(client, clean_tab_id)
    wait_text(clean_pages['popup'], popup_text, {'popup_noDetails': initial_catalog['popup_noDetails']['message'],
                                                'vt_disabled': initial_catalog['vt_disabled']['message']})
    languages = {'en': 'This message', 'es': 'Este mensaje', 'de': 'Diese Nachricht',
                 'fr': 'Ce message', 'it': 'Questo messaggio', 'el': 'Αυτό το μήνυμα',
                 'ru': 'Это письмо', 'zh_CN': '这封邮件'}
    result['widgetProbe'] = {}
    for phase in ('initial', *languages, 'auto'):
        choice = 'auto' if phase == 'initial' else phase
        if phase != 'initial':
            widget_page_script(client, pages['options'], """
              const select = document.querySelector('#uiLanguage');
              select.value = arguments[0];
              select.dispatchEvent(new Event('change', {bubbles:true}));
            """, [choice])
        catalog = read_catalog(auto_locale if choice == 'auto' else choice, choice == 'auto')
        lang = initial['lang'] if choice == 'auto' else choice.replace('_', '-')
        code = lang.replace('-', '_')
        if code not in languages:
            code = code.split('_')[0]
        opts = {'options_title': catalog['options_title']['message'],
                'options_languageAuto': catalog['options_languageAuto']['message'],
                'selection': choice, 'ready': True, 'lang': lang}

        def expected_popup(empty):
            nums = (0, 0, 0) if empty else (1, 1, 0)
            expected = {key: catalog[key]['message'] for key in (
                'ui_buyCoffee', 'ui_openOptions', 'popup_summary', 'popup_senderDomain',
                'vt_title', 'vt_setup', 'vt_disabled')}
            expected.update(lang=lang, popup_thisMessage=languages.get(code, languages['en']),
                            counts=[str(n) for n in nums], popup_noDetails=catalog['popup_noDetails']['message'] if empty else None)
            for name, num in zip(('alert', 'image', 'link'), nums):
                singular = code != 'zh_CN' and (num == 1 or (num == 0 and code == 'fr'))
                key = 'popup_label_' + name + ('' if singular else 's')
                expected[name] = catalog[key]['message']
            for key in ('reason_onePixel', 'popup_confidence_medium', 'popup_copy'):
                expected[key] = None if empty else catalog[key]['message']
            # Independent of the bundled catalog: these are the formerly
            # untranslated fields actually visible in the reported screenshot.
            if code == 'es' and empty:
                expected.update(alert='alertas', image='imágenes', link='enlaces', popup_summary='Resumen',
                                ui_openOptions='Ajustes', ui_buyCoffee='Invítame a un café',
                                popup_senderDomain='Dominio del remitente', popup_noDetails='Sin detalles')
            return expected

        expected = expected_popup(False)
        empty_expected = expected_popup(True)
        options = wait_text(pages['options'], options_text, opts)
        popup = wait_text(pages['popup'], popup_text, expected)
        empty_popup = wait_text(clean_pages['popup'], popup_text, empty_expected)
        stored = production_tab_script(client, message_tab_id, "browser.storage.local.get('uiLanguage')")
        result['widgetProbe'][phase] = {'options': options, 'popup': popup, 'emptyPopup': empty_popup,
                                       'stored': stored.get('uiLanguage')}
        passed = options == opts and popup == expected and empty_popup == empty_expected
        passed = passed and stored.get('uiLanguage') == (None if phase == 'initial' else choice)
        result['checks'].append({'name': f'widget_{phase}_loaded_and_empty', 'passed': passed})
        if choice == 'es' and passed:
            save_widget_screenshot(client, clean_pages['popup'], run, result)
        if choice == 'it':
            fresh = open_widget_pages(client, message_tab_id)
            reopened_options = wait_text(fresh['options'], options_text, opts)
            reopened_popup = wait_text(fresh['popup'], popup_text, expected)
            result['checks'].append({'name': 'widget_selection_survives_reopening',
                                     'passed': reopened_options == opts and reopened_popup == expected})


def save_widget_screenshot(client, tab_id, run, result):
    bounds = widget_page_script(client, tab_id, """
      const box = document.body.getBoundingClientRect();
      return {width:Math.ceil(box.width), height:Math.ceil(box.height)};
    """)
    data = client.execute_async_script("""
      const [id, size, done] = arguments;
      (async () => {
        const { ExtensionParent } = ChromeUtils.importESModule('resource://gre/modules/ExtensionParent.sys.mjs');
        const ext = ExtensionParent.GlobalManager.getExtension('pixel-guard@enriqueite.com');
        const browser = ext.tabManager.get(id).browser;
        const rect = new DOMRect(0, 0, size.width, size.height);
        const bitmap = await browser.browsingContext.currentWindowGlobal.drawSnapshot(rect, 1, '#ffffff');
        const canvas = browser.ownerDocument.createElementNS('http://www.w3.org/1999/xhtml', 'canvas');
        canvas.width = bitmap.width;
        canvas.height = bitmap.height;
        canvas.getContext('2d').drawImage(bitmap, 0, 0);
        return canvas.toDataURL('image/png').split(',')[1];
      })().then(done, error => done({error:String(error)}));
    """, script_args=[tab_id, bounds])
    if isinstance(data, str):
        import base64
        path = run / 'popup-es.png'
        path.write_bytes(base64.b64decode(data))
        result['spanishPopupScreenshot'] = str(path)


def main():
    root = Path(__file__).resolve().parent.parent
    parser = argparse.ArgumentParser()
    parser.add_argument('--binary', required=True)
    parser.add_argument('--label', default='installed')
    parser.add_argument('--addon', type=Path, help='Exact XPI to install; defaults to source directory')
    parser.add_argument('--helper', action='store_true', help='Run public-API helper with synthetic messages')
    parser.add_argument('--widget-languages', action='store_true',
                        help='Exercise the language selector and translated widget using the synthetic tracking message')
    parser.add_argument('--banner-mode', choices=('fixed', 'compare'), default='fixed',
                        help='Verify silent default and opt-in, or record an older XPI for comparison')
    args = parser.parse_args()
    if args.widget_languages and not args.helper:
        parser.error('--widget-languages requires --helper')
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
                        if 'virustotal/inventory.js' in archive.namelist():
                            inventory = archive.read('virustotal/inventory.js')
                        elif args.banner_mode == 'compare':
                            # Pre-VirusTotal packages still use the same test helper/fixtures.
                            inventory = (root / 'virustotal' / 'inventory.js').read_bytes()
                        else:
                            raise RuntimeError('Release package is missing inventory.js')
                else:
                    inventory = (root / 'virustotal' / 'inventory.js').read_bytes()
                (helper / 'inventory.js').write_bytes(inventory)
                (helper / 'helper.js').write_bytes((root / 'scripts' / 'thunderbird-helper.js').read_bytes())
                endpoint = f'http://127.0.0.1:{server.server_port}'
                (helper / 'config.js').write_text('const QA_ENDPOINT = '+json.dumps(endpoint)+';\n'
                    +'const QA_WIDGET_LANGUAGES = '+json.dumps(args.widget_languages)+';\n',encoding='utf-8')
                Addons(client).install(str(helper),temp=True)
                if not received.wait(45):
                    raise RuntimeError('QA helper did not return a result within 45 seconds')
                result['helper'] = payload
                tab_ids = {check['name']: check['detail']['tabId'] for check in payload.get('checks', [])
                           if check.get('passed') and isinstance(check.get('detail'), dict)
                           and 'tabId' in check['detail']}
                tabs = {'tracking': tab_ids['open_message_tab'], 'ordinary': tab_ids['ordinary_message_tab'],
                        'standalone': tab_ids['standalone_message']}
                check_banner_behavior(client, result, tabs, args.banner_mode)
                if args.widget_languages:
                    check_widget_languages(client, result, tabs['tracking'], tab_ids['clean_message_tab'], addon, run)
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
    server.shutdown()
    if 'helper' in result:
        requests = payload.get('resourceRequests', [])
        result['helper']['resourceRequests'] = requests
        result['checks'].append({'name': 'no_parser_or_message_resource_fetch', 'passed': not requests})
    (run / 'result.json').write_text(json.dumps(result, indent=2), encoding='utf-8')
    print(json.dumps(result, indent=2))
    print(f'Result: {run / "result.json"}')
    failed = ('error' in result or result.get('helper', {}).get('error') or
              result.get('optionsTab', {}).get('error') or
              any(not c['passed'] for c in result['checks']) or
              any(not c['passed'] for c in result.get('helper', {}).get('checks', [])))
    return 1 if failed else 0


if __name__ == '__main__':
    raise SystemExit(main())
