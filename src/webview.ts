import * as vscode from 'vscode';

/**
 * Génère le HTML du panneau Nodock — direction « rétro-futuriste » :
 * scanlines VHS, titre chrome Y2K, coins arrondis, glow néon. La palette
 * suit le thème VS Code de l'utilisateur (variables --vscode-*) : le
 * caractère vient des formes et des effets, jamais de couleurs imposées.
 *
 * Icônes : Lucide (licence ISC) — chemins `d` extraits côté hôte par
 * src/icons.ts et injectés ici en constantes JSON (CSP default-src 'none').
 * Animations d'icônes : morphicons (MIT), embarqué en script module inline
 * par src/morphicons-host.ts ; sans lui, repli sur un changement direct.
 */
export function getWebviewHtml(
  webview: vscode.Webview,
  nonce: string,
  morphLib = '',
  icons: Record<string, string> = {}
): string {
  const csp = `default-src 'none'; style-src 'nonce-${nonce}'; script-src 'nonce-${nonce}'; img-src ${webview.cspSource} https: data:;`;
  // Script module morphicons AVANT le script applicatif, seulement si chargé.
  const morphScript = morphLib
    ? `<script type="module" nonce="${nonce}">${morphLib}</script>\n`
    : '';
  // Icône initiale du bouton Scan (repli : bouclier historique).
  const shieldD = icons['shield'] ?? 'M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z';

  return /* html */ `<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
<meta http-equiv="Content-Security-Policy" content="${csp}">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Nodock</title>
<style nonce="${nonce}">
  :root {
    /* Base 100 % thème VS Code */
    --bg: var(--vscode-sideBar-background);
    --fg: var(--vscode-foreground);
    --muted: var(--vscode-descriptionForeground);
    --border: var(--vscode-panel-border, rgba(128,128,128,.25));
    --accent: var(--vscode-textLink-foreground);
    --focus: var(--vscode-focusBorder, var(--vscode-textLink-foreground));
    --btn-bg: var(--vscode-button-background);
    --btn-fg: var(--vscode-button-foreground);
    --btn-hover: var(--vscode-button-hoverBackground);
    --card: var(--vscode-editor-background);
    /* Accents néon dérivés du thème (avec replis synthwave) */
    --neon-purple: var(--vscode-charts-purple, #9d4edd);
    --neon-blue: var(--vscode-charts-blue, #00b8d4);
    --neon-pink: var(--vscode-terminal-ansiMagenta, #ff2e88);
    --neon-cyan: var(--vscode-terminal-ansiCyan, #00e5ff);
    --critical: var(--vscode-editorError-foreground, #f14c4c);
    --high: var(--vscode-editorWarning-foreground, #f48771);
    --medium: var(--vscode-charts-yellow, #e2c08d);
    --low: var(--vscode-charts-green, #4ec9b0);
    --info: var(--vscode-charts-blue, #75beff);
    /* Glow néon dérivé du focus : lisible sur thème clair comme sombre */
    --glow: color-mix(in srgb, var(--focus) 55%, transparent);
    --radius: 14px;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    font-family: var(--vscode-font-family);
    font-size: var(--vscode-font-size);
    color: var(--fg);
    background: var(--bg);
    padding: 0 0 28px;
  }

  /* ---------- Overlay VHS : scanlines neutres, discrètes sur tout thème ---------- */
  body::after {
    content: '';
    position: fixed; inset: 0; z-index: 999;
    pointer-events: none;
    background: repeating-linear-gradient(0deg,
      rgba(128,128,128,.055) 0px, rgba(128,128,128,.055) 1px,
      transparent 1px, transparent 4px);
  }

  .mono {
    font-family: ui-monospace, 'Courier New', monospace;
    text-transform: uppercase; letter-spacing: .16em;
  }

  /* ---------- Icônes Lucide inline ---------- */
  .ic { display: inline-flex; flex: none; }
  .ic svg { width: 14px; height: 14px; display: block; }
  .btn .ic svg { width: 15px; height: 15px; }
  .tab .ic svg { width: 13px; height: 13px; }
  .note .ic svg { width: 13px; height: 13px; margin-top: 1px; }
  .action .ic svg { width: 11px; height: 11px; }
  .err .ic svg { width: 12px; height: 12px; }
  .fix .ic svg { width: 12px; height: 12px; }
  .sev-ic { display: inline-flex; flex: none; margin-top: 1px; }
  .sev-ic svg { width: 16px; height: 16px; }

  /* ---------- Header ---------- */
  header {
    display: flex; align-items: center; gap: 12px;
    padding: 18px 14px 12px;
  }
  .logo { width: 36px; height: 36px; flex: none; filter: drop-shadow(0 0 5px var(--glow)); }
  .logo .shield {
    fill: none; stroke: var(--neon-purple); stroke-width: 1.6;
    stroke-linecap: round; stroke-linejoin: round;
    stroke-dasharray: 60; stroke-dashoffset: 60;
    animation: draw 1.6s ease forwards;
  }
  .logo .check {
    fill: none; stroke: var(--low); stroke-width: 2;
    stroke-linecap: round; stroke-linejoin: round;
    stroke-dasharray: 12; stroke-dashoffset: 12;
    animation: draw 0.8s ease 1.2s forwards;
  }
  @keyframes draw { to { stroke-dashoffset: 0; } }
  /* Titre « chrome » Y2K : dégradé métallique basé sur la couleur du thème */
  h1 {
    font-family: ui-monospace, 'Courier New', monospace;
    font-size: 19px; font-weight: 800;
    letter-spacing: .18em; text-transform: uppercase;
    background: linear-gradient(180deg,
      color-mix(in srgb, var(--fg) 50%, var(--bg)) 0%,
      var(--fg) 36%,
      color-mix(in srgb, var(--fg) 22%, var(--bg)) 50%,
      var(--fg) 63%,
      color-mix(in srgb, var(--fg) 68%, var(--bg)) 100%);
    -webkit-background-clip: text; background-clip: text;
    color: transparent;
    animation: flicker 7s linear infinite;
  }
  /* Flicker VHS très léger */
  @keyframes flicker {
    0%, 91%, 94%, 96.5%, 100% { opacity: 1; }
    92% { opacity: .55; }
    93% { opacity: .9; }
    95% { opacity: .7; }
  }
  header p {
    font-family: ui-monospace, 'Courier New', monospace;
    font-size: 10px; color: var(--muted);
    text-transform: uppercase; letter-spacing: .18em;
    margin-top: 2px;
  }

  /* ---------- Tabs ---------- */
  .tabs {
    display: flex; gap: 6px; padding: 4px 14px 0;
    border-bottom: 1px solid var(--border);
  }
  .tab {
    display: inline-flex; align-items: center; gap: 7px;
    background: none; border: 1px solid transparent; border-bottom: none;
    border-radius: 10px 10px 0 0;
    color: var(--muted);
    font-family: ui-monospace, 'Courier New', monospace;
    font-size: 11px; font-weight: 700;
    text-transform: uppercase; letter-spacing: .12em;
    padding: 8px 12px; cursor: pointer;
    position: relative;
    transition: color .2s, background .2s;
  }
  .tab:hover { color: var(--fg); }
  .tab.active { color: var(--accent); background: var(--card); border-color: var(--border); }
  /* Souligné néon dégradé */
  .tab.active::after {
    content: ''; position: absolute; left: 10px; right: 10px; bottom: -1px;
    height: 2px; border-radius: 2px;
    background: linear-gradient(90deg, var(--neon-purple), var(--neon-blue));
    box-shadow: 0 0 8px var(--glow);
  }
  .panel { display: none; padding: 14px; }
  .panel.active { display: block; animation: fadein .25s ease; }
  @keyframes fadein { from { opacity: 0; transform: translateY(4px); } to { opacity: 1; transform: none; } }

  /* ---------- Boutons ---------- */
  .btn {
    display: inline-flex; align-items: center; gap: 7px;
    background: var(--btn-bg); color: var(--btn-fg);
    border: 1px solid transparent; border-radius: 12px;
    font: inherit; font-size: 12px; font-weight: 600;
    padding: 8px 14px; cursor: pointer;
    transition: background .15s, transform .1s, box-shadow .2s, border-color .2s;
  }
  .btn:hover { background: var(--btn-hover); box-shadow: 0 0 14px -3px var(--glow); }
  .btn:active { transform: scale(.97); }
  .btn.ghost {
    background: transparent; color: var(--accent);
    border: 1px solid var(--border);
  }
  .btn.ghost:hover {
    background: var(--vscode-toolbar-hoverBackground, rgba(128,128,128,.15));
    border-color: var(--focus);
  }
  .btn:disabled { opacity: .55; cursor: wait; }
  .actions { display: flex; gap: 8px; margin-bottom: 12px; }

  /* ---------- Spinner ---------- */
  .spin {
    width: 12px; height: 12px; border-radius: 50%;
    border: 2px solid currentColor; border-top-color: transparent;
    animation: rot .7s linear infinite; display: none;
  }
  .loading .spin { display: inline-block; }
  .loading .morph, .loading .ic { display: none; }
  @keyframes rot { to { transform: rotate(360deg); } }

  /* ---------- Score + rang arcade ---------- */
  .score {
    display: flex; align-items: center; gap: 14px;
    background:
      linear-gradient(135deg, color-mix(in srgb, var(--neon-purple) 8%, transparent), transparent 55%),
      var(--card);
    border: 1px solid var(--border);
    border-radius: 16px; padding: 14px; margin-bottom: 12px;
  }
  .ring { width: 64px; height: 64px; flex: none; transform: rotate(-90deg); }
  .ring .track { fill: none; stroke: var(--border); stroke-width: 6; }
  .ring .val {
    fill: none; stroke-width: 6; stroke-linecap: round;
    transition: stroke-dashoffset 1s ease, stroke .5s;
    filter: drop-shadow(0 0 4px var(--glow));
  }
  .score-num {
    font-family: ui-monospace, 'Courier New', monospace;
    font-size: 22px; font-weight: 800; letter-spacing: .04em;
  }
  .score-label { font-size: 11px; color: var(--muted); margin-top: 2px; max-width: 160px; }
  /* Portée et fraîcheur du rapport : un rapport mémorisé doit se voir. */
  .scan-info { font-size: 10px; color: var(--muted); margin-top: 3px; opacity: .85; }
  .scan-info.stale { color: var(--medium); opacity: 1; font-weight: 600; }
  .rank { margin-left: auto; text-align: center; flex: none; }
  .rank-letter {
    font-family: ui-monospace, 'Courier New', monospace;
    font-size: 36px; font-weight: 900; line-height: 1;
  }
  .rank-letter.rS { color: var(--neon-purple); text-shadow: 0 0 12px color-mix(in srgb, var(--neon-purple) 70%, transparent); }
  .rank-letter.rA { color: var(--low); text-shadow: 0 0 12px color-mix(in srgb, var(--low) 70%, transparent); }
  .rank-letter.rB { color: var(--neon-blue); text-shadow: 0 0 12px color-mix(in srgb, var(--neon-blue) 70%, transparent); }
  .rank-letter.rC { color: var(--medium); text-shadow: 0 0 10px color-mix(in srgb, var(--medium) 70%, transparent); }
  .rank-letter.rD { color: var(--critical); text-shadow: 0 0 10px color-mix(in srgb, var(--critical) 70%, transparent); }
  .rank-tag { font-size: 9px; color: var(--muted); margin-top: 3px; }

  /* ---------- Chips (filtres de sévérité) ---------- */
  .chips { display: flex; flex-wrap: wrap; gap: 6px; margin-bottom: 12px; }
  .chip {
    display: inline-flex; align-items: center; gap: 5px;
    font-family: ui-monospace, 'Courier New', monospace;
    font-size: 10px; font-weight: 700;
    text-transform: uppercase; letter-spacing: .08em;
    padding: 4px 10px; border-radius: 999px;
    border: 1px solid var(--border);
    background: var(--card); color: var(--muted);
    cursor: pointer; transition: all .15s;
  }
  .chip .dot { width: 7px; height: 7px; border-radius: 50%; box-shadow: 0 0 5px currentColor; }
  .chip.active { color: var(--fg); border-color: currentColor; box-shadow: 0 0 10px -3px currentColor; }

  /* ---------- Findings ---------- */
  .group-title {
    font-family: ui-monospace, 'Courier New', monospace;
    font-size: 10px; font-weight: 700; text-transform: uppercase;
    letter-spacing: .14em; color: var(--muted); margin: 16px 0 7px;
    display: flex; align-items: center; gap: 7px;
  }
  .group-title .ic { color: var(--accent); }
  .group-title::after {
    content: ''; flex: 1; height: 1px;
    background: linear-gradient(90deg, var(--border), transparent);
  }
  /**
   * La sévérité colore le contour ENTIER de la carte, en trait fin.
   * Un liseré à gauche seulement se lisait mal une fois la liste dense : le
   * contour complet rattache la couleur à la carte plutôt qu'à son bord.
   */
  .finding {
    background: var(--card);
    border: 1px solid var(--sev, var(--border));
    border-radius: 12px; padding: 10px 12px; margin-bottom: 8px;
    cursor: pointer;
    transition: transform .12s, border-color .2s, box-shadow .2s;
    animation: fadein .3s ease;
  }
  .finding:hover { transform: translateX(3px); box-shadow: 0 0 14px -6px var(--glow); }
  .finding.critical { --sev: var(--critical); }
  .finding.high { --sev: var(--high); }
  .finding.medium { --sev: var(--medium); }
  .finding.low, .finding.info { --sev: var(--low); }
  .finding .top { display: flex; align-items: flex-start; gap: 8px; }
  .morph { width: 16px; height: 16px; flex: none; margin-top: 1px; }
  .finding .title { font-size: 12px; font-weight: 600; line-height: 1.35; }
  .finding .meta { font-size: 11px; color: var(--muted); margin-top: 3px; }
  .finding .desc { display: none; font-size: 11px; color: var(--muted); margin-top: 6px; line-height: 1.5; }
  .finding.open .desc { display: block; }
  .badge {
    font-family: ui-monospace, 'Courier New', monospace;
    font-size: 9px; font-weight: 800; text-transform: uppercase;
    letter-spacing: .08em;
    padding: 3px 8px; border-radius: 8px; flex: none;
  }
  .badge.critical { background: color-mix(in srgb, var(--critical) 20%, transparent); color: var(--critical); }
  .badge.high { background: color-mix(in srgb, var(--high) 20%, transparent); color: var(--high); }
  .badge.medium { background: color-mix(in srgb, var(--medium) 20%, transparent); color: var(--medium); }
  .badge.low, .badge.info { background: color-mix(in srgb, var(--low) 20%, transparent); color: var(--low); }
  .fix {
    display: flex; align-items: center; gap: 5px;
    font-size: 11px; color: var(--low); margin-top: 5px; font-weight: 600;
  }
  .tags { display: flex; flex-wrap: wrap; gap: 5px; margin-top: 5px; }
  .tag {
    font-size: 10px; font-weight: 700; color: var(--muted);
    border: 1px solid var(--border); border-radius: 6px; padding: 1px 6px;
  }
  .verdict {
    font-family: ui-monospace, 'Courier New', monospace;
    font-size: 9px; font-weight: 800; text-transform: uppercase;
    letter-spacing: .08em; padding: 2px 7px; border-radius: 6px;
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
    display: inline-flex; align-items: center; gap: 5px;
    background: none; border: 1px solid var(--border); border-radius: 8px;
    color: var(--accent); font: inherit; font-size: 11px; font-weight: 600;
    padding: 3px 9px; cursor: pointer;
    transition: border-color .15s, box-shadow .15s;
  }
  .action:hover {
    background: var(--vscode-toolbar-hoverBackground, rgba(128,128,128,.15));
    border-color: var(--focus);
  }

  /* ---------- Avertissements de scan ---------- */
  .notes { margin-bottom: 10px; }
  .note {
    display: flex; gap: 7px; font-size: 11px; line-height: 1.45;
    color: var(--muted); background: var(--card);
    border: 1px solid var(--border); border-left: 3px solid var(--medium);
    border-radius: 10px; padding: 7px 10px; margin-bottom: 5px;
  }
  .note .ic { color: var(--medium); }

  .empty {
    text-align: center; color: var(--muted); font-size: 12px;
    padding: 30px 10px; line-height: 1.7;
  }
  .empty .big {
    display: flex; justify-content: center; margin-bottom: 10px;
    color: var(--accent);
  }
  .empty .big svg {
    width: 34px; height: 34px; stroke-width: 1.5;
    filter: drop-shadow(0 0 6px var(--glow));
  }
  .pulse svg { animation: pulse 1.2s ease-in-out infinite; }
  @keyframes pulse { 0%, 100% { opacity: 1; } 50% { opacity: .35; } }

  /* ---------- News ---------- */
  .news-item {
    background: var(--card); border: 1px solid var(--border);
    border-radius: 12px; padding: 10px 12px; margin-bottom: 8px;
    cursor: pointer; transition: transform .12s, border-color .2s, box-shadow .2s;
    animation: fadein .3s ease;
  }
  .news-item:hover { transform: translateX(3px); border-color: var(--focus); box-shadow: 0 0 14px -6px var(--glow); }
  .news-item .title { font-size: 12px; font-weight: 600; line-height: 1.4; }
  .news-item .meta { font-size: 10px; color: var(--muted); margin-top: 4px; display: flex; gap: 8px; }
  .news-item .src {
    color: var(--accent); font-weight: 700; text-transform: uppercase;
    letter-spacing: .5px;
  }
  .news-item .sum { font-size: 11px; color: var(--muted); margin-top: 5px; line-height: 1.5; }
  .err {
    display: flex; align-items: center; gap: 5px;
    font-size: 11px; color: var(--high); padding: 4px 0;
  }

  /* ---------- Accessibilité : on coupe toutes les animations ---------- */
  @media (prefers-reduced-motion: reduce) {
    *, *::before, *::after {
      animation-duration: .01ms !important;
      animation-iteration-count: 1 !important;
      transition-duration: .01ms !important;
    }
  }
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
    <p>Scanner de vulnérabilités · RT-88</p>
  </div>
</header>

<div class="tabs">
  <button class="tab active" data-tab="scan"><span class="ic" data-ic="shield"></span>Scan</button>
  <button class="tab" data-tab="news"><span class="ic" data-ic="newspaper"></span>Actualités</button>
</div>

<!-- ============ PANEL SCAN ============ -->
<div class="panel active" id="panel-scan">
  <div class="actions">
    <button class="btn" id="btn-scan">
      <span class="spin"></span>
      <svg class="morph" viewBox="0 0 24 24" fill="none" stroke="currentColor"
           stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
        <path id="scan-icon" d="${shieldD}"/>
      </svg>
      <span>Scanner le projet</span>
    </button>
    <button class="btn ghost" id="btn-export" title="Exporter le rapport (JSON/SARIF)"><span class="ic" data-ic="download"></span></button>
    <button class="btn ghost" id="btn-legal" title="Générer les mentions légales (RGPD)"><span class="ic" data-ic="scale"></span></button>
  </div>
  <div id="scan-status" class="empty">
    <span class="ic big" data-ic="shield"></span>
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
        <div class="scan-info" id="scan-info"></div>
      </div>
      <div class="rank">
        <div class="rank-letter" id="score-rank">–</div>
        <div class="rank-tag mono">Rang</div>
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
      <span class="spin"></span><span class="ic" data-ic="refresh-cw"></span> Actualiser
    </button>
  </div>
  <div id="news-errors"></div>
  <div id="news-list"><div class="empty"><span class="ic big" data-ic="newspaper"></span>Chargement des actualités…</div></div>
</div>

${morphScript}<script nonce="${nonce}">
  const vscode = acquireVsCodeApi();
  // Icônes Lucide (ISC) injectées par l'hôte ; morphicons (MIT) éventuellement
  // présent via window.NDK_MORPH — le panneau fonctionne sans.
  const ICONS = ${JSON.stringify(icons)};
  const MORPH = window.NDK_MORPH;

  let allFindings = [];
  let allNotes = [];
  let activeFilter = null;
  let reportScore = null;
  let previousScore = null;
  let scanMorph = null;
  let idleTimer = null;

  // ---------- Icônes inline ----------
  function svgIcon(name, cls) {
    const d = ICONS[name] || ICONS.info || '';
    return '<span class="ic' + (cls ? ' ' + cls : '') + '"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="' + d + '"/></svg></span>';
  }
  // Remplace les emplacements data-ic du HTML statique par les SVG Lucide.
  document.querySelectorAll('[data-ic]').forEach((el) => {
    const tmp = document.createElement('span');
    tmp.innerHTML = svgIcon(el.getAttribute('data-ic'));
    const node = tmp.firstChild;
    if (el.className && el.className !== 'ic') node.setAttribute('class', el.className);
    el.replaceWith(node);
  });

  // ---------- Icône du bouton Scan : morphing bouclier -> états ----------
  const scanIconEl = document.getElementById('scan-icon');
  function scanIcon(name) {
    const d = ICONS[name] || ICONS.shield || '';
    if (!d) return;
    if (MORPH && typeof MORPH.createMorph === 'function') {
      if (!scanMorph) scanMorph = MORPH.createMorph(scanIconEl, d);
      else scanMorph.morphTo(d, 'snappy');
    } else {
      // Repli sans morphicons : changement d'icône direct, sans animation.
      scanIconEl.setAttribute('d', d);
    }
  }
  function backToShieldSoon() {
    if (idleTimer) clearTimeout(idleTimer);
    idleTimer = setTimeout(() => scanIcon('shield'), 4000);
  }

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

  // Couleurs de sévérité : variables du thème (avec replis) pour rester
  // cohérent sur thème clair comme sombre.
  const SEV_COLOR = {
    critical: 'var(--vscode-editorError-foreground, #f14c4c)',
    high: 'var(--vscode-editorWarning-foreground, #f48771)',
    medium: 'var(--vscode-charts-yellow, #e2c08d)',
    low: 'var(--vscode-charts-green, #4ec9b0)',
    info: 'var(--vscode-charts-blue, #75beff)'
  };
  const SEV_LABEL = { critical:'Critique', high:'Élevée', medium:'Moyenne', low:'Faible', info:'Info' };
  const SEV_ICON = { critical:'zap', high:'triangle-alert', medium:'triangle-alert', low:'info', info:'info' };
  const KIND_LABEL = { audit:'Audit de posture', websec:'Vulnérabilités applicatives', infra:'Conteneurs & CI/CD', dependency:'Dépendances', secret:'Secrets', sast:'Code (SAST)', attack:'Vecteurs d\\'attaque', standards:'Normes de codage', rgpd:'Conformité & Mentions légales' };
  const KIND_ICON = { audit:'radar', websec:'globe', infra:'terminal', dependency:'bug', secret:'lock-keyhole', sast:'file-code-2', attack:'crosshair', standards:'list-checks', rgpd:'scale' };
  const VERDICT_LABEL = { probable:'Exploitable', 'a-verifier':'À vérifier', improbable:'Aucun chemin détecté' };

  // Pastille de sévérité d'un finding (Lucide, couleur du thème).
  function iconFor(sev) {
    return '<span class="sev-ic" style="color:' + SEV_COLOR[sev] + '">' +
      svgIcon(SEV_ICON[sev] || 'info') + '</span>';
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
    for (const kind of ['audit','websec','infra','dependency','secret','sast','attack','standards','rgpd']) {
      const group = list.filter(f => f.kind === kind);
      if (!group.length) continue;
      const h = document.createElement('div');
      h.className = 'group-title';
      h.innerHTML = svgIcon(KIND_ICON[kind] || 'info') +
        '<span>' + KIND_LABEL[kind] + ' (' + group.length + ')</span>';
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
          (f.fixedVersion ? '<div class="fix">' + svgIcon('circle-check') + ' Corrigé dans : ' + esc(f.fixedVersion) + '</div>' : '') +
          (f.triage ? '<div class="why"><b>Pourquoi ce verdict</b><br>' +
            f.triage.reasons.map(r => '• ' + esc(r)).join('<br>') + '</div>' : '') +
          '<div class="row-actions">' +
          (f.url ? '<button class="action" data-act="url">' + svgIcon('external-link') + ' Ouvrir l\\'avis</button>' : '') +
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

  /** Compteur animé du score (count-up) ; instantané si reduced-motion. */
  function animateScore(target) {
    const el = document.getElementById('score-num');
    const reduced = typeof matchMedia !== 'undefined' &&
      matchMedia('(prefers-reduced-motion: reduce)').matches;
    if (reduced || target === 0) { el.textContent = target + '/100'; return; }
    const start = performance.now();
    const dur = 900;
    const frame = (now) => {
      const p = Math.min(1, (now - start) / dur);
      const eased = 1 - Math.pow(1 - p, 3);
      el.textContent = Math.round(target * eased) + '/100';
      if (p < 1) requestAnimationFrame(frame);
    };
    requestAnimationFrame(frame);
  }

  function renderScore(stats) {
    const total = stats.critical + stats.high + stats.medium + stats.low;
    // Le score calculé par l'extension (pondéré par le triage) fait foi ;
    // repli sur le barème historique pour les anciens rapports persistés.
    let score = reportScore;
    if (typeof score !== 'number') {
      score = 100 - (stats.critical * 25 + stats.high * 10 + stats.medium * 4 + stats.low * 1);
      score = Math.max(0, Math.min(100, score));
    }
    const color = score >= 80 ? 'var(--vscode-charts-green, #4ec9b0)'
      : score >= 50 ? 'var(--vscode-charts-yellow, #e2c08d)'
      : 'var(--vscode-editorError-foreground, #f14c4c)';
    animateScore(score);
    let label =
      total === 0 ? 'Aucune vulnérabilité détectée' :
      total + ' problème' + (total > 1 ? 's' : '') + ' détecté' + (total > 1 ? 's' : '');
    if (typeof previousScore === 'number' && previousScore !== score) {
      const delta = score - previousScore;
      label += ' — ' + (delta > 0 ? '+' : '') + delta + ' pts vs scan précédent';
    }
    document.getElementById('score-label').textContent = label;
    // Gamification : le score devient un rang arcade (S ≥ 90, A ≥ 75,
    // B ≥ 55, C ≥ 35, D sinon), affiché à côté de l'anneau.
    const rank = score >= 90 ? 'S' : score >= 75 ? 'A' : score >= 55 ? 'B' : score >= 35 ? 'C' : 'D';
    const rankEl = document.getElementById('score-rank');
    rankEl.textContent = rank;
    rankEl.className = 'rank-letter r' + rank;
    const ring = document.getElementById('ring-val');
    const C = 163.3;
    ring.style.stroke = color;
    ring.style.strokeDashoffset = C - (C * score / 100);
  }

  function renderNotes() {
    document.getElementById('notes').innerHTML = (allNotes || [])
      .map(n => '<div class="note">' + svgIcon('file-warning') + '<span>' + esc(n) + '</span></div>')
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

  /** « il y a 3 min », « il y a 2 j »… pour dater le rapport affiché. */
  function since(iso) {
    const ms = Date.now() - new Date(iso).getTime();
    if (!isFinite(ms) || ms < 0) return '';
    const min = Math.floor(ms / 60000);
    if (min < 1) return 'à l\\'instant';
    if (min < 60) return 'il y a ' + min + ' min';
    const h = Math.floor(min / 60);
    if (h < 24) return 'il y a ' + h + ' h';
    return 'il y a ' + Math.floor(h / 24) + ' j';
  }

  /**
   * Ce que le scan a réellement couvert, et quand.
   *
   * Le panneau réaffiche le dernier rapport mémorisé à chaque ouverture : sans
   * cette ligne, un rapport ancien — ou vide — est indiscernable d'un scan qui
   * vient de tourner. Les compteurs disent aussi tout de suite si le scan a
   * bien vu le projet.
   */
  function renderScanInfo(report) {
    const el = document.getElementById('scan-info');
    if (!el) return;
    const s = report.stats || {};
    const parts = [];
    if (typeof s.filesScanned === 'number') parts.push(s.filesScanned + ' fichiers analysés');
    if (typeof s.dependenciesScanned === 'number') parts.push(s.dependenciesScanned + ' dépendances vérifiées');
    // Distingue « rien à signaler » de « tout a été masqué » ou « rien n'est remonté ».
    if (typeof s.collected === 'number') parts.push(s.collected + ' trouvés');
    if (s.ignored) parts.push(s.ignored + ' masqués');
    if (report.version) parts.push('v' + report.version);
    const age = report.generatedAt ? since(report.generatedAt) : '';
    if (age) parts.push(age);
    el.textContent = parts.join(' · ');
    // Un rapport de plus d'une heure mérite d'être signalé comme tel.
    const stale = report.generatedAt && Date.now() - new Date(report.generatedAt).getTime() > 3600000;
    el.className = stale ? 'scan-info stale' : 'scan-info';
  }

  /** Affiche un rapport et le mémorise : le panneau est détruit dès qu'il est masqué. */
  function showReport(report, persist) {
    allFindings = report.findings || [];
    allNotes = report.notes || [];
    reportScore = typeof report.score === 'number' ? report.score : null;
    previousScore = typeof report.previousScore === 'number' ? report.previousScore : null;
    activeFilter = null;
    document.getElementById('scan-status').style.display = 'none';
    document.getElementById('scan-results').style.display = 'block';
    renderAll();
    renderScanInfo(report);
    if (persist) vscode.setState({ report: report });
  }

  // ---------- Messages de l'extension ----------
  window.addEventListener('message', (e) => {
    const msg = e.data;
    if (msg.type === 'scanStart') {
      if (idleTimer) { clearTimeout(idleTimer); idleTimer = null; }
      btnScan.classList.add('loading');
      btnScan.disabled = true;
      scanIcon('refresh-cw'); // bouclier -> rafraîchissement pendant le scan
      document.getElementById('scan-status').style.display = 'block';
      document.getElementById('scan-status').innerHTML =
        '<span class="ic big pulse">' + svgIcon('radar') + '</span>' + esc(msg.step || 'Analyse en cours…');
      document.getElementById('scan-results').style.display = 'none';
    }
    if (msg.type === 'scanStep') {
      document.getElementById('scan-status').innerHTML =
        '<span class="ic big pulse">' + svgIcon('radar') + '</span>' + esc(msg.step);
    }
    if (msg.type === 'report') {
      btnScan.classList.remove('loading');
      btnScan.disabled = false;
      const crit = msg.report && msg.report.stats ? msg.report.stats.critical : 0;
      scanIcon(crit > 0 ? 'triangle-alert' : 'circle-check');
      backToShieldSoon(); // retour au bouclier au prochain scan
      showReport(msg.report, true);
    }
    if (msg.type === 'scanError') {
      btnScan.classList.remove('loading');
      btnScan.disabled = false;
      scanIcon('triangle-alert');
      backToShieldSoon();
      document.getElementById('scan-status').style.display = 'block';
      document.getElementById('scan-status').innerHTML =
        '<span class="ic big">' + svgIcon('triangle-alert') + '</span>' + esc(msg.error);
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
        (msg.errors || []).map(e => '<div class="err">' + svgIcon('triangle-alert') + ' ' + esc(e) + '</div>').join('');
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
