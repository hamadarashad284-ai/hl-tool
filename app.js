'use strict';
// Hamada License — owner-only key generator (works offline on Mac and iPhone).
// The private key (PKCS#8 PEM) is imported once per device and kept in localStorage encrypted with AES-GCM under a key
// derived from the passcode (PBKDF2, 310k rounds). Keys are "<payload>.<signature>" (base64url), signed with Ed25519 —
// the same format js/license.js verifies inside the extensions.
(()=>{
const $=id=>document.getElementById(id),STORE='hamada.license.v1',LOG='hamada.license.log';
const PRODUCTS={HS:{id:'sync',name:'Hamada Sync'},HK:{id:'keys',name:'Hamada Keys'},HP:{id:'split',name:'Hamada Split'}};
const enc=new TextEncoder(),dec=new TextDecoder();
const b64u=buf=>btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
const b64=buf=>btoa(String.fromCharCode(...new Uint8Array(buf))),unb64=s=>Uint8Array.from(atob(s),c=>c.charCodeAt(0));
let signKey=null;  // CryptoKey, only in memory while unlocked
function show(...ids){for(const s of ['setup','unlock','gen','out','logBox'])$(s).classList.toggle('hidden',!ids.includes(s));$('lockBtn').classList.toggle('hidden',!ids.includes('gen'));}
function msg(id,text,ok){const m=$(id);m.textContent=text||'';m.className='msg '+(ok?'ok':'err');}

// ---- passcode → AES key ----
async function aesKey(pass,salt){const base=await crypto.subtle.importKey('raw',enc.encode(pass),'PBKDF2',false,['deriveKey']);
 return crypto.subtle.deriveKey({name:'PBKDF2',salt,iterations:310000,hash:'SHA-256'},base,{name:'AES-GCM',length:256},false,['encrypt','decrypt']);}
function pemToDer(pem){const body=String(pem).replace(/-----[^-]+-----/g,'').replace(/\s+/g,'');if(!body)throw Error('empty');return unb64(body);}
async function importPrivate(der){return crypto.subtle.importKey('pkcs8',der,{name:'Ed25519'},false,['sign']);}

async function setup(){try{const pem=$('pemText').value.trim(),p1=$('newPass').value,p2=$('newPass2').value;
  if(!pem)return msg('setupMsg','اختر ملف المفتاح السري أو الصق محتواه.');if(p1.length<6)return msg('setupMsg','رمز الدخول يجب أن يكون 6 أرقام أو أكثر.');if(p1!==p2)return msg('setupMsg','الرمزان غير متطابقين.');
  let der;try{der=pemToDer(pem);signKey=await importPrivate(der);}catch(e){return msg('setupMsg',/Ed25519|not supported|Algorithm/i.test(String(e))?'هذا المتصفح لا يدعم التوقيع المطلوب. حدّث Safari أو Chrome.':'هذا ليس ملف مفتاح سري صالح.');}
  const salt=crypto.getRandomValues(new Uint8Array(16)),iv=crypto.getRandomValues(new Uint8Array(12)),k=await aesKey(p1,salt),ct=await crypto.subtle.encrypt({name:'AES-GCM',iv},k,der);
  localStorage.setItem(STORE,JSON.stringify({salt:b64(salt),iv:b64(iv),data:b64(ct)}));$('pemText').value='';$('newPass').value=$('newPass2').value='';openApp();}
 catch(e){msg('setupMsg','تعذّر الحفظ: '+e.message);}}
async function unlock(){const s=JSON.parse(localStorage.getItem(STORE)||'null');if(!s)return show('setup');
 try{const k=await aesKey($('pass').value,unb64(s.salt)),der=await crypto.subtle.decrypt({name:'AES-GCM',iv:unb64(s.iv)},k,unb64(s.data));signKey=await importPrivate(der);$('pass').value='';openApp();}
 catch(e){msg('unlockMsg','رمز الدخول غير صحيح.');}}
function lock(){signKey=null;show('unlock');msg('unlockMsg','');setTimeout(()=>$('pass').focus(),50);}
function openApp(){show('gen','logBox');renderLog();setTimeout(()=>$('code').focus(),50);}

// ---- generate ----
let type='full',last=null;
function normCode(c){const s=String(c||'').toUpperCase().replace(/[^A-Z0-9]/g,'');return s.length===10?s.slice(0,2)+'-'+s.slice(2,6)+'-'+s.slice(6):null;}
function onCode(){const c=normCode($('code').value),p=c&&PRODUCTS[c.slice(0,2)];$('productHint').textContent=c?(p?'الإضافة: '+p.name:'بداية الكود غير معروفة (HS أو HK أو HP).'):'';}
async function generate(){if(!signKey)return lock();const code=normCode($('code').value),p=code&&PRODUCTS[code.slice(0,2)];
 if(!code)return msg('genMsg','اكتب كود الجهاز كما أرسله العميل، مثل HS-7K2M-9QX4.');if(!p)return msg('genMsg','بداية الكود ('+code.slice(0,2)+') غير معروفة في هذه النسخة من الأداة. أغلق الصفحة وافتحها مرة أخرى للحصول على آخر تحديث.');const name=$('name').value.trim();if(!name)return msg('genMsg','اكتب اسم العميل.');
 const now=new Date(),payload={p:p.id,m:code,n:name,t:type,i:now.toISOString().slice(0,10)};
 if(type==='trial'){const days=Math.max(1,Math.min(60,Number($('days').value)||3));payload.e=new Date(now.getTime()+days*86400000).toISOString();}
 const body=b64u(enc.encode(JSON.stringify(payload))),sig=await crypto.subtle.sign({name:'Ed25519'},signKey,enc.encode(body)),key=body+'.'+b64u(sig);
 last={key,payload,product:p.name,phone:$('phone').value.trim()};$('key').value=key;$('outTitle').textContent=(type==='trial'?'مفتاح تجريبي':'مفتاح كامل')+' · '+p.name+' · '+name;
 $('out').classList.remove('hidden');msg('genMsg','');
 const log=JSON.parse(localStorage.getItem(LOG)||'[]');log.unshift({date:now.toISOString(),name,phone:last.phone,product:p.name,code,type,expires:payload.e||''});localStorage.setItem(LOG,JSON.stringify(log));renderLog();
 $('out').scrollIntoView({behavior:'smooth',block:'center'});}
function waText(){const p=last.payload,until=p.t==='trial'?'\nالنسخة التجريبية صالحة حتى '+new Date(p.e).toLocaleDateString('ar')+'.':'';
 return 'أهلًا '+p.n+' 👋\nهذا مفتاح تفعيل '+last.product+':\n\n'+last.key+'\n\nانسخ المفتاح كاملًا، والصقه في شاشة التفعيل داخل الإضافة، ثم اضغط «تفعيل».'+until;}
async function copy(text,btn){try{await navigator.clipboard.writeText(text);}catch(e){const t=document.createElement('textarea');t.value=text;document.body.appendChild(t);t.select();document.execCommand('copy');t.remove();}
 const o=btn.textContent;btn.textContent='تم النسخ ✓';setTimeout(()=>btn.textContent=o,1400);}

// ---- log ----
function renderLog(){const q=$('search').value.trim().toLowerCase(),rows=$('rows'),log=JSON.parse(localStorage.getItem(LOG)||'[]');rows.textContent='';
 for(const r of log.filter(r=>!q||[r.name,r.phone,r.code,r.product].join(' ').toLowerCase().includes(q)).slice(0,300)){const tr=document.createElement('tr');
  const who=document.createElement('td');who.textContent=r.name;const c=document.createElement('code');c.className='small';c.textContent=' '+r.code;who.appendChild(document.createElement('br'));who.appendChild(c);
  const prod=document.createElement('td');prod.textContent=r.product.replace('Hamada ','');
  const kind=document.createElement('td'),tag=document.createElement('span');tag.className='tag '+r.type;tag.textContent=r.type==='trial'?'تجريبي':'كامل';kind.appendChild(tag);
  const date=document.createElement('td');date.textContent=new Date(r.date).toLocaleDateString('ar');tr.append(who,prod,kind,date);rows.appendChild(tr);}
 $('logNote').textContent=log.length+' مفتاح · السجل محفوظ على هذا الجهاز فقط. صدّره لحفظ نسخة.';}
function exportCSV(){const log=JSON.parse(localStorage.getItem(LOG)||'[]'),esc=v=>'"'+String(v||'').replace(/"/g,'""')+'"';
 const csv='﻿'+['التاريخ,العميل,الهاتف,الإضافة,كود الجهاز,النوع,ينتهي'].concat(log.map(r=>[r.date.slice(0,10),r.name,r.phone,r.product,r.code,r.type==='trial'?'تجريبي':'كامل',r.expires.slice(0,10)].map(esc).join(','))).join('\n');
 const a=document.createElement('a');a.href=URL.createObjectURL(new Blob([csv],{type:'text/csv'}));a.download='hamada-customers-'+new Date().toISOString().slice(0,10)+'.csv';a.click();}

// ---- wire up ----
$('pemFile').onchange=async e=>{const f=e.target.files[0];if(f)$('pemText').value=await f.text();};
$('setupBtn').onclick=setup;$('unlockBtn').onclick=unlock;$('pass').onkeydown=e=>{if(e.key==='Enter')unlock();};$('lockBtn').onclick=lock;
$('resetBtn').onclick=()=>{if(confirm('سيُحذف المفتاح السري المحفوظ على هذا الجهاز (سجل العملاء يبقى). هل تريد المتابعة؟')){localStorage.removeItem(STORE);show('setup');}};
$('code').oninput=onCode;$('genBtn').onclick=generate;$('search').oninput=renderLog;$('exportBtn').onclick=exportCSV;
$('type').querySelectorAll('button').forEach(b=>b.onclick=()=>{type=b.dataset.v;$('type').querySelectorAll('button').forEach(x=>x.classList.toggle('on',x===b));$('trialBox').classList.toggle('hidden',type!=='trial');});
$('copyKey').onclick=e=>copy(last.key,e.target);
$('sendWa').onclick=()=>{const phone=(last.phone||'').replace(/[^0-9]/g,'');window.open('https://wa.me/'+phone+'?text='+encodeURIComponent(waText()),'_blank');};
// Lock again after 10 minutes in the background.
let hiddenAt=0;document.addEventListener('visibilitychange',()=>{if(document.hidden)hiddenAt=Date.now();else if(signKey&&Date.now()-hiddenAt>600000)lock();});
if('serviceWorker' in navigator&&location.protocol==='https:')navigator.serviceWorker.register('sw.js').catch(()=>{});
if(!window.crypto||!crypto.subtle){document.body.insertAdjacentHTML('beforeend','<section><p>افتح الصفحة عبر https أو من الجهاز نفسه ليعمل التشفير.</p></section>');}
localStorage.getItem(STORE)?lock():show('setup');
})();
