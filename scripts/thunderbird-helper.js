// Test-only addon background. Uses public APIs; never included in release XPI.
/* global browser, PixelGuardVTInventory, QA_ENDPOINT */
(async () => {
  const checks = [];
  const check = (name, pass, detail) => {
    checks.push({name, passed: !!pass, detail});
    if (!pass) throw new Error('Failed: ' + name);
  };
  try {
    const html = '<html><head><style>@import "'+QA_ENDPOINT+'/resource/import.css";</style></head><body>'+
      '<a href="https://example.invalid/normal">Normal</a><p>https://example.invalid/text.</p>'+
      '<img src="'+QA_ENDPOINT+'/resource/image.png" width="1" height="1">'+
      '<iframe src="'+QA_ENDPOINT+'/resource/frame"></iframe>'+
      '<div style="background:url('+QA_ENDPOINT+'/resource/background.png)">Box</div></body></html>';
    const inventory=PixelGuardVTInventory.collectLinks({contentType:'text/html',body:html});
    check('native_extension_DOMParser_inventory',inventory.links.length===2&&inventory.links.some(l=>l.url==='https://example.invalid/text'),inventory.links.map(l=>l.url));
    await new Promise(resolve=>setTimeout(resolve,700));
    const eml='From: QA <sender@example.invalid>\r\nTo: QA <recipient@example.invalid>\r\n'+
      'Subject: PixelGuard synthetic runtime test\r\nDate: Wed, 11 Nov 2026 00:00:00 +0000\r\n'+
      'Message-ID: <pixelguard-runtime@example.invalid>\r\nMIME-Version: 1.0\r\n'+
      'Content-Type: multipart/mixed; boundary="pgqa"\r\n\r\n'+
      '--pgqa\r\nContent-Type: text/html; charset=UTF-8\r\n\r\n'+html+'\r\n'+
      '--pgqa\r\nContent-Type: text/plain; name="sample.txt"\r\n'+
      'Content-Disposition: attachment; filename="sample.txt"\r\nContent-Transfer-Encoding: base64\r\n\r\nYWJj\r\n--pgqa--\r\n';
    const file=new File([eml],'synthetic.eml',{type:'message/rfc822'});
    const tab=await browser.messageDisplay.open({file,location:'tab',active:true});
    const message=await browser.messageDisplay.getDisplayedMessage(tab.id);
    check('open_message_tab',!!message?.id,{tabId:tab.id,messageId:message?.id});
    const full=await browser.messages.getFull(message.id);
    check('getFull',!!full?.parts?.length,{contentType:full.contentType,parts:full.parts?.length});
    const fromMessage=PixelGuardVTInventory.collectLinks(full);
    check('real_message_inventory',fromMessage.links.length===2&&fromMessage.links.some(l=>l.url==='https://example.invalid/text'),fromMessage.links.map(l=>l.url));
    const attachments=await browser.messages.listAttachments(message.id);
    check('listAttachments',attachments.length===1&&attachments[0].name==='sample.txt',attachments);
    const attachment=await browser.messages.getAttachmentFile(message.id,attachments[0].partName);
    const digest=await crypto.subtle.digest('SHA-256',await attachment.arrayBuffer());
    const hash=Array.from(new Uint8Array(digest),n=>n.toString(16).padStart(2,'0')).join('');
    check('attachment_SHA256',hash==='ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad',{size:attachment.size,hash});
    const separate=await browser.messageDisplay.open({file,location:'window'});
    const displayed=await browser.messageDisplay.getDisplayedMessage(separate.id);
    check('standalone_message',!!displayed?.id,{tabId:separate.id,messageId:displayed?.id});
    await browser.windows.remove(separate.windowId);
    await new Promise(resolve=>setTimeout(resolve,700));
    await fetch(QA_ENDPOINT+'/result',{method:'POST',body:JSON.stringify({checks,note:'Public Thunderbird APIs with synthetic File; production inventory bytes in helper addon; no liveVT or UI permission grant.'})});
  } catch(e) {
    await fetch(QA_ENDPOINT+'/result',{method:'POST',body:JSON.stringify({checks,error:String(e),stack:e.stack})});
  }
})();
