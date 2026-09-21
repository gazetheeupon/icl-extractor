const $ = (id) => document.getElementById(id);

let currentGroups = null;
let currentFileBase = 'icons';

function setStatus(msg, isError) {
  const el = $('status');
  el.textContent = msg || '';
  el.classList.toggle('error', !!isError);
}

function escapeHtml(s) {
  return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

function formatBytes(n) {
  if (n < 1024) return n + ' B';
  if (n < 1024 * 1024) return (n / 1024).toFixed(1) + ' KB';
  return (n / (1024 * 1024)).toFixed(2) + ' MB';
}

function sanitizeName(s) {
  return String(s).replace(/[^A-Za-z0-9._-]+/g, '_').replace(/^_+|_+$/g, '') || 'icon';
}

async function handleFile(file) {
  $('fname').textContent = file.name;
  currentFileBase = (file.name || 'icons').replace(/\.[^.]+$/, '');
  setStatus('Reading and parsing…');
  ['summaryCard', 'groupsCard'].forEach((id) => { $(id).style.display = 'none'; });
  currentGroups = null;
  try {
    const buf = await file.arrayBuffer();
    const parsed = IclParser.parseIclBuffer(buf);
    currentGroups = parsed.groups;
    render(parsed);
    setStatus(`Found ${parsed.groupCount} icon group(s), ${parsed.totalIconImages} image(s) total.`);
  } catch (err) {
    setStatus((err && err.message) || String(err), true);
  }
}

function render(parsed) {
  $('summaryCard').style.display = '';
  $('summaryBody').innerHTML = `
    <tr><td>Architecture</td><td>${escapeHtml(parsed.architecture)}</td></tr>
    <tr><td>File size</td><td>${formatBytes(parsed.fileSize)}</td></tr>
    <tr><td>Icon groups</td><td>${parsed.groupCount}</td></tr>
    <tr><td>Total images</td><td>${parsed.totalIconImages}</td></tr>
  `;

  $('groupsCard').style.display = '';
  $('groupCount').textContent = `${parsed.groups.length} group(s)`;
  const list = $('groupsList');
  list.innerHTML = '';
  parsed.groups.forEach((g, idx) => {
    const row = document.createElement('div');
    row.className = 'group-row';

    const blob = new Blob([g.icoBytes], { type: 'image/vnd.microsoft.icon' });
    const url = URL.createObjectURL(blob);

    const previews = document.createElement('div');
    previews.className = 'group-previews';
    // Show up to 3 size variants as <img> (browsers can render .ico
    // directly); the OS/browser will itself pick a representative frame.
    const shown = Math.min(3, g.sizes.length);
    for (let i = 0; i < shown; i++) {
      const img = document.createElement('img');
      img.src = url;
      img.alt = '';
      previews.appendChild(img);
    }

    const info = document.createElement('div');
    info.className = 'group-info';
    const sizesLabel = g.sizes.map((s) => `${s.width}×${s.height}`).join(', ');
    info.innerHTML = `<div class="group-label">${escapeHtml(g.label)}</div><div class="group-sizes">${escapeHtml(sizesLabel)} &middot; ${formatBytes(g.icoBytes.length)}</div>`;

    const btn = document.createElement('button');
    btn.className = 'dl';
    btn.textContent = 'Download .ico';
    btn.addEventListener('click', () => {
      const a = document.createElement('a');
      a.href = url;
      a.download = `${sanitizeName(currentFileBase)}_${sanitizeName(g.label)}.ico`;
      a.click();
    });

    row.appendChild(previews);
    row.appendChild(info);
    row.appendChild(btn);
    list.appendChild(row);
  });
}

async function downloadAllZip() {
  if (!currentGroups || !currentGroups.length) return;
  const btn = $('downloadAllBtn');
  btn.disabled = true;
  const prevText = btn.textContent;
  btn.textContent = 'Zipping…';
  try {
    const zip = new JSZip();
    const used = new Set();
    for (const g of currentGroups) {
      let name = `${sanitizeName(currentFileBase)}_${sanitizeName(g.label)}.ico`;
      let n = 1;
      while (used.has(name)) {
        name = `${sanitizeName(currentFileBase)}_${sanitizeName(g.label)}_${n++}.ico`;
      }
      used.add(name);
      zip.file(name, g.icoBytes);
    }
    const blob = await zip.generateAsync({ type: 'blob' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = `${sanitizeName(currentFileBase)}_icons.zip`;
    a.click();
  } catch (err) {
    setStatus('Error building ZIP: ' + ((err && err.message) || String(err)), true);
  } finally {
    btn.disabled = false;
    btn.textContent = prevText;
  }
}

function bindDrop() {
  const dz = $('dropzone');
  const input = $('fileInput');
  const setDrag = (on) => dz.classList.toggle('drag', on);
  ['dragenter', 'dragover'].forEach((ev) => dz.addEventListener(ev, (e) => { e.preventDefault(); setDrag(true); }));
  ['dragleave', 'drop'].forEach((ev) => dz.addEventListener(ev, (e) => { e.preventDefault(); setDrag(false); }));
  dz.addEventListener('drop', (e) => {
    const file = e.dataTransfer.files && e.dataTransfer.files[0];
    if (file) handleFile(file);
  });
  dz.addEventListener('click', () => input.click());
  dz.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); input.click(); }
  });
  input.addEventListener('change', () => {
    if (input.files && input.files[0]) handleFile(input.files[0]);
    input.value = '';
  });
}

bindDrop();
$('downloadAllBtn').addEventListener('click', downloadAllZip);
