import * as vscode from 'vscode';

/** Génère le HTML du panneau Nodock (suit automatiquement le thème VS Code). */
export function getWebviewHtml(webview: vscode.Webview, nonce: string): string {
  const csp = `default-src 'none'; style-src 'unsafe-inline'; script-src 'nonce-${nonce}'; img-src ${webview.cspSource} https: data:;`;

  return /* html */ `<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
<meta http-equiv="Content-Security-Policy" content="${csp}">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Nodock</title>
<style>
  :root {
    --bg: var(--vscode-sideBar-background);
    --fg: var(--vscode-foreground);
    --muted: var(--vscode-descriptionForeground);
    --border: var(--vscode-panel-border, rgba(128,128,128,.25));
    --accent: var(--vscode-textLink-foreground);
    --btn-bg: var(--vscode-button-background);
    --btn-fg: var(--vscode-button-foreground);
    --btn-hover: var(--vscode-button-hoverBackground);
    --card: var(--vscode-editor-background);
    --critical: #f14c4c;
    --high: #f48771;
    --medium: #e2c08d;
    --low: #4ec9b0;
    --info: #75beff;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    font-family: var(--vscode-font-family);
    font-size: var(--vscode-font-size);
    color: var(--fg);
    background: var(--bg);
    padding: 0 0 24px;
  }

  /* ---------- Header ---------- */
  header {
    display: flex; align-items: center; gap: 10px;
    padding: 16px 14px 10px;
  }
  .logo { width: 34px; height: 34px; flex: none; }
  .logo .shield {
    fill: none; stroke: var(--accent); stroke-width: 1.8;
    stroke-linecap: round; stroke-linejoin: round;
    stroke-dasharray: 60; stroke-dashoffset: 60;
    animation: draw 1.6s ease forwards, glow 3s ease-in-out 1.6s infinite;
  }
  .logo .check {
    fill: none; stroke: var(--low); stroke-width: 2;
    stroke-linecap: round; stroke-linejoin: round;
    stroke-dasharray: 12; stroke-dashoffset: 12;
    animation: draw 0.8s ease 1.2s forwards;
  }
  @keyframes draw { to { stroke-dashoffset: 0; } }
  @keyframes glow {
    0%, 100% { filter: drop-shadow(0 0 1px var(--accent)); }
    50% { filter: drop-shadow(0 0 5px var(--accent)); }
  }
  h1 { font-size: 17px; font-weight: 700; letter-spacing: .4px; }
  header p { font-size: 11px; color: var(--muted); }

  /* ---------- Tabs ---------- */
  .tabs {
    display: flex; gap: 4px; padding: 4px 14px 0;
    border-bottom: 1px solid var(--border);
  }
  .tab {
    background: none; border: none; color: var(--muted);
    font: inherit; font-size: 12px; font-weight: 600;
    padding: 7px 10px; cursor: pointer;
    border-bottom: 2px solid transparent;
    transition: color .2s, border-color .2s;
  }
  .tab:hover { color: var(--fg); }
  .tab.active { color: var(--accent); border-bottom-color: var(--accent); }
  .panel { display: none; padding: 12px 14px; }
  .panel.active { display: block; animation: fadein .25s ease; }
  @keyframes fadein { from { opacity: 0; transform: translateY(4px); } to { opacity: 1; transform: none; } }

  /* ---------- Boutons ---------- */
  .btn {
    display: inline-flex; align-items: center; gap: 6px;
    background: var(--btn-bg); color: var(--btn-fg);
    border: none; border-radius: 4px; font: inherit; font-size: 12px;
    font-weight: 600; padding: 7px 12px; cursor: pointer;
    transition: background .15s, transform .1s;
  }
  .btn:hover { background: var(--btn-hover); }
  .btn:active { transform: scale(.97); }
  .btn.ghost {
    background: transparent; color: var(--accent);
    border: 1px solid var(--border);
  }
  .btn.ghost:hover { background: var(--vscode-toolbar-hoverBackground, rgba(128,128,128,.15)); }
  .btn:disabled { opacity: .55; cursor: wait; }
  .actions { display: flex; gap: 8px; margin-bottom: 12px; }

  /* ---------- Spinner ---------- */
  .spin {
    width: 12px; height: 12px; border-radius: 50%;
    border: 2px solid var(--btn-fg); border-top-color: transparent;
    animation: rot .7s linear infinite; display: none;
  }
  .loading .spin { display: inline-block; }
  @keyframes rot { to { transform: rotate(360deg); } }

  /* ---------- Score ---------- */
  .score {
    display: flex; align-items: center; gap: 14px;
    background: var(--card); border: 1px solid var(--border);
    border-radius: 8px; padding: 12px; margin-bottom: 12px;
  }
  .ring { width: 64px; height: 64px; flex: none; transform: rotate(-90deg); }
  .ring .track { fill: none; stroke: var(--border); stroke-width: 6; }
  .ring .val {
    fill: none; stroke-width: 6; stroke-linecap: round;
    transition: stroke-dashoffset 1s ease, stroke .5s;
  }
  .score-num { font-size: 22px; font-weight: 800; }
  .score-label { font-size: 11px; color: var(--muted); }

  .chips { display: flex; flex-wrap: wrap; gap: 6px; margin-bottom: 12px; }
  .chip {
    display: inline-flex; align-items: center; gap: 5px;
    font-size: 11px; font-weight: 700;
    padding: 3px 9px; border-radius: 999px;
    border: 1px solid var(--border);
    background: var(--card); color: var(--muted);
    cursor: pointer; transition: all .15s;
  }
  .chip .dot { width: 7px; height: 7px; border-radius: 50%; }
  .chip.active { color: var(--fg); border-color: currentColor; }

  /* ---------- Findings ---------- */
  .group-title {
    font-size: 11px; font-weight: 700; text-transform: uppercase;
    letter-spacing: .8px; color: var(--muted); margin: 14px 0 6px;
    display: flex; align-items: center; gap: 6px;
  }
  .finding {
    background: var(--card); border: 1px solid var(--border);
    border-left: 3px solid var(--border);
    border-radius: 6px; padding: 9px 11px; margin-bottom: 7px;
    cursor: pointer;
    transition: transform .12s, border-color .2s;
    animation: fadein .3s ease;
  }
  .finding:hover { transform: translateX(3px); }
  .finding.critical { border-left-color: var(--critical); }
  .finding.high { border-left-color: var(--high); }
  .finding.medium { border-left-color: var(--medium); }
  .finding.low, .finding.info { border-left-color: var(--low); }
  .finding .top { display: flex; align-items: flex-start; gap: 8px; }
  .morph { width: 16px; height: 16px; flex: none; margin-top: 1px; }
  .morph path {
    fill: none; stroke-width: 2; stroke-linecap: round; stroke-linejoin: round;
    transition: d .35s ease;
  }
  .finding .title { font-size: 12px; font-weight: 600; line-height: 1.35; }
  .finding .meta { font-size: 11px; color: var(--muted); margin-top: 3px; }
  .finding .desc { display: none; font-size: 11px; color: var(--muted); margin-top: 6px; line-height: 1.5; }
  .finding.open .desc { display: block; }
  .badge {
    font-size: 10px; font-weight: 800; text-transform: uppercase;
    padding: 2px 7px; border-radius: 4px; flex: none;
  }
  .badge.critical { background: color-mix(in srgb, var(--critical) 20%, transparent); color: var(--critical); }
  .badge.high { background: color-mix(in srgb, var(--high) 20%, transparent); color: var(--high); }
  .badge.medium { background: color-mix(in srgb, var(--medium) 20%, transparent); color: var(--medium); }
  .badge.low, .badge.info { background: color-mix(in srgb, var(--low) 20%, transparent); color: var(--low); }
  .fix { font-size: 11px; color: var(--low); margin-top: 4px; font-weight: 600; }
  .tags { display: flex; flex-wrap: wrap; gap: 5px; margin-top: 5px; }
  .tag {
    font-size: 10px; font-weight: 700; color: var(--muted);
    border: 1px solid var(--border); border-radius: 3px; padding: 1px 5px;
  }
  .verdict {
    font-size: 10px; font-weight: 800; text-transform: uppercase;
    letter-spacing: .3px; padding: 1px 6px; border-radius: 3px;
  }
  .verdict.probable { background: color-mix(in srgb, var(--critical) 20%, transparent); color: var(--critical); }
  .verdict.a-verifier { background: color-mix(in srgb, var(--medium) 20%, transparent); color: var(--medium); }
  .verdict.improbable { background: color-mix(in srgb, var(--muted) 18%, transparent); color: var(--muted); }
  .finding.improbable { opacity: .72; }
  .finding.improbable:hover { opacity: 1; }
  .why {
    font-size: 11px; line-height: 1.5; color: var(--muted);
    border-left: 2px solid var(--border); padding-left: 8px; margin-top: 8px;
  }
  .why b { color: var(--fg); font-weight: 700; }
  .row-actions { display: flex; flex-wrap: wrap; gap: 6px; margin-top: 8px; }
  .action {
    background: none; border: 1px solid var(--border); border-radius: 4px;
    color: var(--accent); font: inherit; font-size: 11px; font-weight: 600;
    padding: 3px 8px; cursor: pointer;
  }
  .action:hover { background: var(--vscode-toolbar-hoverBackground, rgba(128,128,128,.15)); }

  /* ---------- Avertissements de scan ---------- */
  .notes { margin-bottom: 10px; }
  .note {
    display: flex; gap: 6px; font-size: 11px; line-height: 1.45;
    color: var(--muted); background: var(--card);
    border: 1px solid var(--border); border-left: 3px solid var(--medium);
    border-radius: 4px; padding: 6px 9px; margin-bottom: 5px;
  }

  .empty {
    text-align: center; color: var(--muted); font-size: 12px;
    padding: 30px 10px; line-height: 1.7;
  }
  .empty .big { font-size: 30px; display: block; margin-bottom: 8px; }

  /* ---------- News ---------- */
  .news-item {
    background: var(--card); border: 1px solid var(--border);
    border-radius: 6px; padding: 10px 12px; margin-bottom: 8px;
    cursor: pointer; transition: transform .12s, border-color .2s;
    animation: fadein .3s ease;
  }
  .news-item:hover { transform: translateX(3px); border-color: var(--accent); }
  .news-item .title { font-size: 12px; font-weight: 600; line-height: 1.4; }
  .news-item .meta { font-size: 10px; color: var(--muted); margin-top: 4px; display: flex; gap: 8px; }
  .news-item .src {
    color: var(--accent); font-weight: 700; text-transform: uppercase;
    letter-spacing: .5px;
  }
  .news-item .sum { font-size: 11px; color: var(--muted); margin-top: 5px; line-height: 1.5; }
  .err { font-size: 11px; color: var(--high); padding: 4px 0; }
</style>
</head>
<body>

<header>
  <svg class="logo" viewBox="0 0 24 24">
    <path class="shield" d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
    <path class="check" d="M9 12l2 2 4-4"/>
  </svg>
  <div>
    <h1>Nodock</h1>
    <p>Scanner de vulnérabilités</p>
  </div>
</header>

<div class="tabs">
  <button class="tab active" data-tab="scan">🛡 Scan</button>
  <button class="tab" data-tab="news">📰 Actualités</button>
</div>

<!-- ============ PANEL SCAN ============ -->
<div class="panel active" id="panel-scan">
  <div class="actions">
    <button class="btn" id="btn-scan">
      <span class="spin"></span>
      <svg class="morph" viewBox="0 0 24 24"><path id="scan-icon" stroke="currentColor" d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
      Scanner le projet
    </button>
    <button class="btn ghost" id="btn-export" title="Exporter le rapport (JSON/SARIF)">⤓</button>
    <button class="btn ghost" id="btn-legal" title="Générer les mentions légales (RGPD)">⚖</button>
  </div>
  <div id="scan-status" class="empty">
    <span class="big">🛡️</span>
    Lancez un scan pour analyser vos dépendances,<br>vos secrets et votre code.
  </div>
  <div id="scan-results" style="display:none">
    <div class="score">
      <svg class="ring" viewBox="0 0 60 60">
        <circle class="track" cx="30" cy="30" r="26"/>
        <circle class="val" id="ring-val" cx="30" cy="30" r="26"
          stroke-dasharray="163.3" stroke-dashoffset="163.3" stroke="#4ec9b0"/>
      </svg>
      <div>
        <div class="score-num" id="score-num">—</div>
        <div class="score-label" id="score-label">Score de sécurité</div>
      </div>
    </div>
    <div class="notes" id="notes"></div>
    <div class="chips" id="chips"></div>
    <div id="findings"></div>
  </div>
</div>

<!-- ============ PANEL NEWS ============ -->
<div class="panel" id="panel-news">
  <div class="actions">
    <button class="btn ghost" id="btn-news">
      <span class="spin"></span> ⟳ Actualiser
    </button>
  </div>
  <div id="news-errors"></div>
  <div id="news-list"><div class="empty"><span class="big">📰</span>Chargement des actualités…</div></div>
</div>

<script nonce="${nonce}">
  const vscode = acquireVsCodeApi();
  let allFindings = [];
  let allNotes = [];
  let activeFilter = null;

  // ---------- Tabs ----------
  document.querySelectorAll('.tab').forEach(t => {
    t.addEventListener('click', () => {
      document.querySelectorAll('.tab').forEach(x => x.classList.remove('active'));
      document.querySelectorAll('.panel').forEach(x => x.classList.remove('active'));
      t.classList.add('active');
      document.getElementById('panel-' + t.dataset.tab).classList.add('active');
    });
  });

  // ---------- Actions ----------
  const btnScan = document.getElementById('btn-scan');
  const btnNews = document.getElementById('btn-news');
  btnScan.addEventListener('click', () => vscode.postMessage({ command: 'scan' }));
  btnNews.addEventListener('click', () => vscode.postMessage({ command: 'refreshNews' }));
  document.getElementById('btn-export').addEventListener('click', () => vscode.postMessage({ command: 'exportReport' }));
  document.getElementById('btn-legal').addEventListener('click', () => vscode.postMessage({ command: 'legalNotice' }));

  const SEV_COLOR = { critical:'#f14c4c', high:'#f48771', medium:'#e2c08d', low:'#4ec9b0', info:'#75beff' };
  const SEV_LABEL = { critical:'Critique', high:'Élevée', medium:'Moyenne', low:'Faible', info:'Info' };
  const KIND_LABEL = { dependency:'📦 Dépendances', secret:'🔑 Secrets', sast:'🐛 Code (SAST)', rgpd:'⚖️ Conformité mondiale & Mentions légales' };
  const VERDICT_LABEL = { probable:'Exploitable', 'a-verifier':'À vérifier', improbable:'Aucun chemin détecté' };

  // Icône morph : bouclier -> alerte au survol
  function iconFor(sev) {
    const c = SEV_COLOR[sev];
    return '<svg class="morph" viewBox="0 0 24 24">' +
      '<path stroke="' + c + '" d="M12 9v4M12 17h.01M10.3 3.9 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z"/></svg>';
  }

  function esc(s) {
    return String(s ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
  }

  function renderChips(stats) {
    const wrap = document.getElementById('chips');
    const counts = { critical: stats.critical, high: stats.high, medium: stats.medium, low: stats.low };
    wrap.innerHTML = '';
    for (const sev of ['critical','high','medium','low']) {
      const chip = document.createElement('button');
      chip.className = 'chip' + (activeFilter === sev ? ' active' : '');
      chip.style.color = activeFilter === sev ? SEV_COLOR[sev] : '';
      chip.innerHTML = '<span class="dot" style="background:' + SEV_COLOR[sev] + '"></span>' +
        SEV_LABEL[sev] + ' · ' + counts[sev];
      chip.addEventListener('click', () => {
        activeFilter = activeFilter === sev ? null : sev;
        renderAll();
      });
      wrap.appendChild(chip);
    }
  }

  function renderFindings() {
    const wrap = document.getElementById('findings');
    wrap.innerHTML = '';
    let list = activeFilter ? allFindings.filter(f => f.severity === activeFilter) : allFindings;
    if (!list.length) {
      wrap.innerHTML = '<div class="empty">Aucun résultat pour ce filtre.</div>';
      return;
    }
    for (const kind of ['dependency','secret','sast','rgpd']) {
      const group = list.filter(f => f.kind === kind);
      if (!group.length) continue;
      const h = document.createElement('div');
      h.className = 'group-title';
      h.textContent = KIND_LABEL[kind] + ' (' + group.length + ')';
      wrap.appendChild(h);
      for (const f of group) {
        const tags = [];
        if (f.cvss) tags.push(f.cvss);
        if (f.cwe) tags.push(f.cwe);
        if (f.imprecise) tags.push('version estimée (pas de lockfile)');

        const v = f.triage && f.triage.verdict;
        if (f.direct === false) tags.push('transitive');

        const el = document.createElement('div');
        el.className = 'finding ' + f.severity + (v ? ' ' + v : '');
        el.innerHTML =
          '<div class="top">' + iconFor(f.severity) +
          '<div style="flex:1"><div class="title">' + esc(f.title) + '</div>' +
          '<div class="meta">' + (f.file ? esc(f.file) + (f.line ? ':' + f.line : '') : '') +
          (f.id ? ' · ' + esc(f.id) : '') + '</div>' +
          (v ? '<div class="tags"><span class="verdict ' + v + '">' + VERDICT_LABEL[v] + '</span></div>' : '') +
          (tags.length ? '<div class="tags">' + tags.map(t => '<span class="tag">' + esc(t) + '</span>').join('') + '</div>' : '') +
          '</div>' +
          '<span class="badge ' + f.severity + '">' + SEV_LABEL[f.severity] + '</span></div>' +
          // NB : double échappement obligatoire dans les regex ci-dessous — ce code
          // est produit depuis un template literal, qui consomme un niveau d'échappement.
          '<div class="desc">' + esc(f.description).replace(/\\*\\*(.*?)\\*\\*/g, '<strong>$1</strong>').replace(/\\n/g, '<br>') +
          (f.fixedVersion ? '<div class="fix">✅ Corrigé dans : ' + esc(f.fixedVersion) + '</div>' : '') +
          (f.triage ? '<div class="why"><b>Pourquoi ce verdict</b><br>' +
            f.triage.reasons.map(r => '• ' + esc(r)).join('<br>') + '</div>' : '') +
          '<div class="row-actions">' +
          (f.url ? '<button class="action" data-act="url">Ouvrir l\\'avis ↗</button>' : '') +
          (f.file ? '<button class="action" data-act="file">Ouvrir le fichier</button>' : '') +
          '</div></div>';

        // Clic sur la carte = déplier / replier, rien d'autre.
        el.addEventListener('click', () => el.classList.toggle('open'));

        const urlBtn = el.querySelector('[data-act="url"]');
        if (urlBtn) urlBtn.addEventListener('click', (ev) => {
          ev.stopPropagation();
          vscode.postMessage({ command: 'openUrl', url: f.url });
        });
        const fileBtn = el.querySelector('[data-act="file"]');
        if (fileBtn) fileBtn.addEventListener('click', (ev) => {
          ev.stopPropagation();
          vscode.postMessage({ command: 'openFile', file: f.file, line: f.line });
        });

        wrap.appendChild(el);
      }
    }
  }

  function renderScore(stats) {
    const total = stats.critical + stats.high + stats.medium + stats.low;
    let score = 100 - (stats.critical * 25 + stats.high * 10 + stats.medium * 4 + stats.low * 1);
    score = Math.max(0, Math.min(100, score));
    const color = score >= 80 ? '#4ec9b0' : score >= 50 ? '#e2c08d' : '#f14c4c';
    document.getElementById('score-num').textContent = score + '/100';
    document.getElementById('score-label').textContent =
      total === 0 ? 'Aucune vulnérabilité détectée 🎉' :
      total + ' problème' + (total > 1 ? 's' : '') + ' détecté' + (total > 1 ? 's' : '');
    const ring = document.getElementById('ring-val');
    const C = 163.3;
    ring.style.stroke = color;
    ring.style.strokeDashoffset = C - (C * score / 100);
  }

  function renderNotes() {
    document.getElementById('notes').innerHTML = (allNotes || [])
      .map(n => '<div class="note"><span>⚠</span><span>' + esc(n) + '</span></div>')
      .join('');
  }

  function renderAll() {
    const stats = { critical:0, high:0, medium:0, low:0 };
    allFindings.forEach(f => { if (stats[f.severity] !== undefined) stats[f.severity]++; });
    renderScore(stats);
    renderNotes();
    renderChips(stats);
    renderFindings();
  }

  /** Affiche un rapport et le mémorise : le panneau est détruit dès qu'il est masqué. */
  function showReport(report, persist) {
    allFindings = report.findings || [];
    allNotes = report.notes || [];
    activeFilter = null;
    document.getElementById('scan-status').style.display = 'none';
    document.getElementById('scan-results').style.display = 'block';
    renderAll();
    if (persist) vscode.setState({ report: report });
  }

  // ---------- Messages de l'extension ----------
  window.addEventListener('message', (e) => {
    const msg = e.data;
    if (msg.type === 'scanStart') {
      btnScan.classList.add('loading');
      btnScan.disabled = true;
      document.getElementById('scan-status').style.display = 'block';
      document.getElementById('scan-status').innerHTML = '<span class="big">⏳</span>' + esc(msg.step || 'Analyse en cours…');
      document.getElementById('scan-results').style.display = 'none';
    }
    if (msg.type === 'scanStep') {
      document.getElementById('scan-status').innerHTML = '<span class="big">⏳</span>' + esc(msg.step);
    }
    if (msg.type === 'report') {
      btnScan.classList.remove('loading');
      btnScan.disabled = false;
      showReport(msg.report, true);
    }
    if (msg.type === 'scanError') {
      btnScan.classList.remove('loading');
      btnScan.disabled = false;
      document.getElementById('scan-status').style.display = 'block';
      document.getElementById('scan-status').innerHTML = '<span class="big">⚠️</span>' + esc(msg.error);
    }
    if (msg.type === 'newsStart') {
      btnNews.classList.add('loading');
      btnNews.disabled = true;
    }
    if (msg.type === 'news') {
      btnNews.classList.remove('loading');
      btnNews.disabled = false;
      const list = document.getElementById('news-list');
      list.innerHTML = '';
      if (!msg.items.length) {
        list.innerHTML = '<div class="empty">Aucune actualité disponible.</div>';
      }
      for (const n of msg.items) {
        const el = document.createElement('div');
        el.className = 'news-item';
        el.innerHTML =
          '<div class="title">' + esc(n.title) + '</div>' +
          '<div class="meta"><span class="src">' + esc(n.source) + '</span><span>' + esc(n.date) + '</span></div>' +
          (n.summary ? '<div class="sum">' + esc(n.summary) + '</div>' : '');
        el.addEventListener('click', () => vscode.postMessage({ command: 'openUrl', url: n.url }));
        list.appendChild(el);
      }
      document.getElementById('news-errors').innerHTML =
        (msg.errors || []).map(e => '<div class="err">⚠ ' + esc(e) + '</div>').join('');
    }
  });

  // ---------- Restauration ----------
  // VS Code détruit le webview dès que la vue est masquée : on réaffiche
  // immédiatement le dernier rapport connu, puis on signale qu'on est prêt.
  const saved = vscode.getState();
  if (saved && saved.report) showReport(saved.report, false);

  vscode.postMessage({ command: 'ready' });
  vscode.postMessage({ command: 'refreshNews' });
</script>
</body>
</html>`;
}
