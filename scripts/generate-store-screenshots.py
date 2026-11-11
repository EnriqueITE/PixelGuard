"""Capture the actual extension UI with synthetic data, without external requests.

Requires Microsoft Edge (override with --browser). Screenshots are illustrative,
not native Thunderbird or authenticated VirusTotal test evidence. No key is used.
"""
import argparse
import html
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import time
import uuid


SCENARIOS = [
    ('01-tracking-overview', 'popup', 'overview'),
    ('02-virustotal-links-and-attachments', 'popup', 'inventory'),
    ('03-full-url-confirmation', 'popup', 'confirmation'),
    ('04-optional-setup', 'options', 'setup'),
    ('05-saved-key', 'options', 'saved'),
]
COPY = {
    'en': {
        'label': 'THUNDERBIRD EXTENSION', 'demo': 'Illustrative UI · Synthetic message data',
        'overview': ('Understand the signals.', 'Review possible tracking pixels, external images and tracking links in one panel.', 'PixelGuard reports evidence. Thunderbird controls remote content.'),
        'inventory': ('More context, when you choose.', 'Look up message-link domains and attachment hashes with your own VirusTotal API key.', 'Optional and manual. Attachment contents are never uploaded.'),
        'confirmation': ('See what you share.', 'Review the complete URL before explicitly confirming a lookup.', 'Domain-only lookups remain available. Opening this panel sends no query.'),
        'setup': ('Your choice from the start.', 'VirusTotal is disabled by default. Review the disclosure before granting optional permissions.', 'Your own API key and account terms apply.'),
        'saved': ('Saved, without revealing it.', 'A clear saved-key indicator lets you keep, replace or delete your key.', 'The saved state shown here is simulated. No real key is used.'),
    },
    'es': {
        'label': 'EXTENSIÓN PARA THUNDERBIRD', 'demo': 'Interfaz ilustrativa · Datos de ejemplo',
        'overview': ('Entiende las señales.', 'Revisa posibles píxeles de rastreo, imágenes externas y enlaces de seguimiento desde el panel.', 'PixelGuard muestra indicios. Thunderbird controla el contenido remoto.'),
        'inventory': ('Más contexto, cuando tú quieras.', 'Consulta dominios de enlaces y huellas de adjuntos con tu propia clave de VirusTotal.', 'Opcional y manual. Nunca se sube el contenido de los adjuntos.'),
        'confirmation': ('Mira qué vas a compartir.', 'Revisa la URL completa antes de confirmar expresamente la consulta.', 'También puedes consultar solo el dominio. Abrir el panel no envía consultas.'),
        'setup': ('Tú decides desde el principio.', 'VirusTotal está desactivado inicialmente. Revisa qué datos se envían antes de conceder los permisos opcionales.', 'Se aplican las condiciones de tu cuenta y de tu propia clave.'),
        'saved': ('Guardada, sin mostrarla.', 'El indicador de clave guardada deja claro cómo conservar, reemplazar o eliminar tu clave.', 'El estado guardado está simulado. No se utiliza ninguna clave real.'),
    },
}

MOCK = r"""
const uiCalls = [];
window.browser = {
  i18n: { getMessage: (key, subs = []) => {
    const entry = previewMessages[key]; if (!entry) return key;
    let value = entry.message;
    for (const [name, info] of Object.entries(entry.placeholders || {})) {
      const content = info.content.replace(/\$(\d+)/g, (_, n) => subs[Number(n) - 1] || '');
      value = value.replaceAll('$' + name + '$', content);
    }
    return value.replace(/\$(\d+)/g, (_, n) => subs[Number(n) - 1] || '');
  } },
  storage: { onChanged: { addListener() {} } },
  permissions: { onRemoved: { addListener() {} }, request: async () => false },
  runtime: {
    openOptionsPage: async () => {},
    sendMessage: async message => {
      uiCalls.push(message.type);
      if (message.type === 'pg:getState') return { debug: false };
      if (message.type === 'pg:getFindings') {
        const findings = { suspicious: [], externals: [], links: [] };
        if (previewScenario === 'overview') {
          findings.suspicious.push({host:'metrics.example.com', url:'https://metrics.example.com/open/pixel.gif?id=demo',confidence:'high',reason:'Tiny external image (1 × 1) with a recipient identifier'});
          findings.externals.push({host:'images.example.com',url:'https://images.example.com/newsletter-header.png',confidence:'low',reason:'Visible external image'});
          findings.links.push({host:'news.example.com',url:'https://news.example.com/read?utm_source=newsletter',confidence:'medium',reason:'Link contains campaign tracking parameters'});
        }
        return {domain:'example.com',findings};
      }
      if (message.type === 'pg:vt:getConfig') return {ok:true,enabled:previewScenario !== 'setup',granted:previewScenario !== 'setup',configured:previewScenario !== 'setup'};
      if (message.type === 'pg:vt:getInventory') return {ok:true,sessionId:'demo',links:[{id:'link',host:'example.com',url:'https://example.com/newsletter?campaign=demo'}],attachments:previewScenario === 'confirmation' ? [] : [{id:'file',name:'newsletter.pdf',size:245760}]};
      throw new Error('No outbound actions are allowed in screenshot fixtures.');
    }
  }
};
window.addEventListener('load', () => {
  const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
  (async () => {
    if (previewScenario === 'inventory' || previewScenario === 'confirmation') {
      document.querySelector('#vtSection > summary').click();
      await sleep(150);
      if (previewScenario === 'confirmation') {
        const label = browser.i18n.getMessage('vt_queryUrl');
        [...document.querySelectorAll('#vtInventory button')].find(button => button.textContent === label).click();
      }
    }
    if (previewScenario === 'overview') {
      await sleep(100);
      document.querySelector('.finding-section.external').open = true;
    }
    await sleep(100);
    const result = document.createElement('pre'); result.id = 'screenshot-result'; result.hidden = true;
    result.textContent = JSON.stringify({calls:uiCalls, hasKey:!!document.getElementById('vtKey')?.value});
    document.body.appendChild(result);
  })();
});
"""


def generate(root, browser):
    version = json.loads((root / 'manifest.json').read_text(encoding='utf-8-sig'))['version']
    work = root / 'dist/store-preview'
    work.mkdir(parents=True, exist_ok=True)
    for directory in ['popup', 'options', 'assets']:
        shutil.copytree(root / directory, work / directory, dirs_exist_ok=True)
    startup = subprocess.STARTUPINFO() if os.name == 'nt' else None
    if startup:
        startup.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        startup.wShowWindow = subprocess.SW_HIDE
    results = []
    for lang in ['en', 'es']:
        target = root / 'store-screenshots' / version / lang
        target.mkdir(parents=True, exist_ok=True)
        messages = json.loads((root / '_locales' / lang / 'messages.json').read_text(encoding='utf-8-sig'))
        for filename, page_type, scenario in SCENARIOS:
            item_dir = work / lang / filename
            item_dir.mkdir(parents=True, exist_ok=True)
            source = (root / page_type / (page_type + '.html' if page_type == 'popup' else 'options.html')).read_text(encoding='utf-8')
            source = source.replace('<head>', '<head><base href="' + (work / page_type).as_uri() + '/">')
            first_script = 'popup.js' if page_type == 'popup' else 'options.js'
            mock_url = (item_dir / 'mock.js').as_uri()
            source = source.replace('<script src="' + first_script + '">', '<script src="' + mock_url + '"></script><script src="' + first_script + '">')
            (item_dir / 'ui.html').write_text(source, encoding='utf-8')
            (item_dir / 'mock.js').write_text('const previewMessages=' + json.dumps(messages,ensure_ascii=False) + ';\nconst previewScenario=' + json.dumps(scenario) + ';\n' + MOCK,encoding='utf-8')
            title, description, note = COPY[lang][scenario]
            frame = '''<!doctype html><html><head><meta charset="utf-8"><style>
              *{box-sizing:border-box} body{margin:0;background:#091410;color:#f1fff8;font-family:Segoe UI,Arial,sans-serif;width:1280px;height:960px;overflow:hidden}
              header{position:absolute;left:52px;right:52px;top:38px;display:flex;justify-content:space-between;align-items:center;border-bottom:1px solid #29453a;padding-bottom:23px}
              .brand{font-size:27px;font-weight:750;letter-spacing:-.4px}.version{font-size:14px;color:#a4c7b5;margin-left:13px;font-weight:400}.label{font-size:12px;letter-spacing:1.7px;color:#a4c7b5}
              main{position:absolute;top:145px;left:52px;width:306px} .number{font-size:14px;color:#80e4b3;margin-bottom:19px} h1{font-size:40px;line-height:1.13;letter-spacing:-1.2px;margin:0 0 25px;font-weight:650}
              p{font-size:18px;color:#bdd3c7;line-height:1.6;margin:0 0 30px}.note{border-top:1px solid #29453a;padding-top:22px;font-size:14px;line-height:1.6;color:#9cbaa9}
              .viewport{position:absolute;left:408px;top:130px;width:820px;height:762px;display:flex;justify-content:center;align-items:flex-start;overflow:hidden}
              iframe{border:1px solid #385b4a;border-radius:12px;box-shadow:0 12px 35px #0005;background:#0b0d0f;transform-origin:top center;flex-shrink:0}
              .popup iframe{width:462px;height:650px;transform:scale(1.16)}
              .options iframe{width:920px;height:760px;transform:scale(.88)}
              footer{position:absolute;bottom:24px;left:52px;right:52px;color:#87a996;font-size:12px;display:flex;justify-content:space-between}
            </style></head><body><header><div class="brand">PixelGuard <span class="version">VERSION</span></div><div class="label">LABEL</div></header>
            <main><div class="number">NUMBER / 05</div><h1>TITLE</h1><p>DESCRIPTION</p><div class="note">NOTE</div></main>
            <div class="viewport TYPE"><iframe src="UI" title="PixelGuard interface"></iframe></div>
            <footer><span>DEMO</span><span>PixelGuard · VERSION</span></footer></body></html>'''
            for key, value in {'VERSION':version,'LABEL':COPY[lang]['label'],'NUMBER':filename[:2],'TITLE':title,'DESCRIPTION':description,'NOTE':note,'TYPE':page_type,'UI':(item_dir/'ui.html').as_uri(),'DEMO':COPY[lang]['demo']}.items():
                if key == 'UI':
                    frame = frame.replace('src="UI"', 'src="' + html.escape(value,quote=True) + '"')
                else:
                    frame = frame.replace(key, html.escape(value,quote=True))
            page = item_dir / 'frame.html'
            page.write_text(frame, encoding='utf-8')
            image = target / (filename + '.png')
            profile = work / 'profiles' / (lang + '-' + filename + '-' + uuid.uuid4().hex[:8])
            started = time.time()
            command = [browser,'--headless=new','--disable-gpu','--no-first-run','--no-default-browser-check','--disable-background-networking','--hide-scrollbars','--allow-file-access-from-files','--proxy-server=127.0.0.1:9','--virtual-time-budget=1800','--window-size=1280,960','--force-device-scale-factor=1',f'--user-data-dir={profile}',f'--screenshot={image}',page.as_uri()]
            with (item_dir/'browser.log').open('wb') as log:
                completed = subprocess.run(command,cwd=root,stdout=log,stderr=log,startupinfo=startup,timeout=35)
            while time.time() - started < 20 and (not image.is_file() or image.stat().st_mtime < started):
                time.sleep(.2)
            if not image.is_file() or image.stat().st_mtime < started:
                raise RuntimeError(f'Screenshot failed: {filename}/{lang}; see {item_dir / "browser.log"}')
            width,height = struct.unpack('>II',image.read_bytes()[16:24])
            if (width,height) != (1280,960):
                raise RuntimeError(f'Unexpected image size: {(width,height)}')
            results.append({'file':image.relative_to(root).as_posix(),'width':width,'height':height})
            print(str(image.relative_to(root)),flush=True)
    (work/'results.json').write_text(json.dumps(results,indent=2),encoding='utf-8')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--browser',default=r'C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe')
    args = parser.parse_args()
    generate(Path(__file__).resolve().parent.parent,args.browser)
