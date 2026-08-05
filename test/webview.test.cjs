// Vérifie que le HTML/JS généré pour le panneau est syntaxiquement valide et
// que le nonce CSP est bien propagé. Le webview est une grosse chaîne de
// gabarit : sans ce test, une coquille ne se voit qu'à l'exécution dans VS Code.
const test = require('node:test');
const assert = require('node:assert');
const vm = require('node:vm');

const { getWebviewHtml } = require('../out/webview.js');

const fakeWebview = { cspSource: 'vscode-resource:' };
const NONCE = 'testnonce123';
const html = getWebviewHtml(fakeWebview, NONCE);

test('le script inline est du JavaScript valide', () => {
  const script = html.match(/<script nonce="[^"]+">([\s\S]*?)<\/script>/)?.[1];
  assert.ok(script, 'balise <script> introuvable');
  // Lève une SyntaxError si le script est mal formé (guillemets non échappés…).
  assert.doesNotThrow(() => new vm.Script(script));
});

test('le nonce est appliqué à la CSP et au script', () => {
  assert.ok(html.includes(`script-src 'nonce-${NONCE}'`));
  assert.ok(html.includes(`<script nonce="${NONCE}">`));
  assert.ok(html.includes("default-src 'none'"));
});

test('les conteneurs attendus par le script existent', () => {
  for (const id of ['notes', 'chips', 'findings', 'scan-status', 'scan-results', 'news-list']) {
    assert.ok(html.includes(`id="${id}"`), `#${id} manquant`);
  }
});

test('le rapport est persisté et restauré côté webview', () => {
  assert.ok(html.includes('vscode.setState('), 'le rapport doit être mémorisé');
  assert.ok(html.includes('vscode.getState()'), 'le rapport doit être restauré');
  assert.ok(html.includes("command: 'ready'"), 'le webview doit signaler qu\'il est prêt');
});
