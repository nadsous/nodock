// Tests de la baseline .nodockignore et des exclusions d'exemples.
const test = require('node:test');
const assert = require('node:assert');

const { parseIgnoreFile, applyIgnoreRules, globToRegExp, isIgnored } = require('../out/ignore.js');
const { scanSecretsInText } = require('../out/secrets.js');
const { triageFileFinding } = require('../out/triage.js');

const f = (id, file) => ({ kind: 'sast', severity: 'high', id, file, title: '', description: '' });

test('globToRegExp : joker simple, double, ancrage', () => {
  assert.ok(globToRegExp('src/**').test('src/a/b/c.ts'));
  assert.ok(globToRegExp('src/*.ts').test('src/a.ts'));
  assert.ok(!globToRegExp('src/*.ts').test('src/nested/a.ts'), '* ne traverse pas les dossiers');
  assert.ok(globToRegExp('**/vendor/**').test('apps/x/vendor/lib.js'));
  assert.ok(globToRegExp('/src/rules.ts').test('src/rules.ts'), 'ancrage à la racine');
  assert.ok(!globToRegExp('src/**').test('test/a.ts'));
});

test('parseIgnoreFile : commentaires, chemins, règles, règle+chemin', () => {
  const rules = parseIgnoreFile(`
# baseline Nodock
src/vendor/**
CMP-009
NDK-JS-001 src/rules/**
  `);
  assert.equal(rules.length, 3);
  assert.deepEqual(
    rules.map((r) => [r.ruleId, r.pattern]),
    [
      [undefined, 'src/vendor/**'],
      ['CMP-009', undefined],
      ['NDK-JS-001', 'src/rules/**'],
    ]
  );
});

test('un chemin seul masque tous les findings du dossier', () => {
  const rules = parseIgnoreFile('src/vendor/**');
  const { kept, ignored } = applyIgnoreRules(
    [f('NDK-JS-001', 'src/vendor/lib.js'), f('CMP-009', 'src/vendor/a/b.js'), f('NDK-JS-001', 'src/app.ts')],
    rules
  );
  assert.equal(ignored, 2);
  assert.equal(kept.length, 1);
  assert.equal(kept[0].file, 'src/app.ts');
});

test('une règle seule est masquée partout', () => {
  const rules = parseIgnoreFile('CMP-009');
  const { kept, ignored } = applyIgnoreRules(
    [f('CMP-009', 'a.ts'), f('CMP-009', 'b/c.ts'), f('CMP-010', 'a.ts')],
    rules
  );
  assert.equal(ignored, 2);
  assert.equal(kept[0].id, 'CMP-010');
});

test('règle + chemin ne masque que la combinaison', () => {
  const rules = parseIgnoreFile('NDK-JS-001 src/rules/**');
  const { kept } = applyIgnoreRules(
    [f('NDK-JS-001', 'src/rules/sast.ts'), f('NDK-JS-001', 'src/app.ts'), f('CMP-009', 'src/rules/x.ts')],
    rules
  );
  assert.equal(kept.length, 2, 'seul le finding visé disparaît');
  assert.ok(kept.some((x) => x.file === 'src/app.ts'));
  assert.ok(kept.some((x) => x.id === 'CMP-009'));
});

test('un dossier sans joker couvre son contenu', () => {
  const rules = parseIgnoreFile('test');
  assert.ok(isIgnored(f('NDK-JS-001', 'test/parsers.test.cjs'), rules));
  assert.ok(!isIgnored(f('NDK-JS-001', 'src/app.ts'), rules));
});

test('une baseline vide ne filtre rien', () => {
  const { kept, ignored } = applyIgnoreRules([f('CMP-009', 'a.ts')], parseIgnoreFile('# rien\n\n'));
  assert.equal(ignored, 0);
  assert.equal(kept.length, 1);
});

test('sans règle, `kept` est un tableau distinct de l\'entrée', () => {
  // Bug constaté en production : `kept` renvoyait la MÊME référence, si bien
  // qu'un appelant vidant `findings` détruisait aussi `kept`. Résultat : sur
  // tout projet sans .nodockignore, les 30 findings disparaissaient et le
  // rapport annonçait « aucune vulnérabilité détectée ».
  const findings = [f('CMP-009', 'a.ts'), f('NDK-JS-001', 'b.ts')];
  const { kept } = applyIgnoreRules(findings, []);
  assert.notEqual(kept, findings, 'doit être un nouveau tableau');

  findings.length = 0; // ce que fait le site d'appel
  assert.equal(kept.length, 2, 'kept doit survivre au vidage de l\'entrée');
});

test('les CVE peuvent être arbitrées dans la baseline', () => {
  const rules = parseIgnoreFile('CVE-2026-53512');
  assert.ok(isIgnored({ id: 'CVE-2026-53512', file: 'bun.lock' }, rules));
  assert.ok(!isIgnored({ id: 'CVE-2026-53514', file: 'bun.lock' }, rules));
});

// ---------------------------------------------------------------------------
test('les clés d\'exemple documentées ne sont plus signalées', () => {
  // Clé publiée dans la documentation AWS : ce n'est pas une fuite.
  assert.equal(scanSecretsInText('const k = "AKIAIOSFODNN7EXAMPLE";', 'a.js').length, 0);
  // Une vraie clé de même forme reste détectée.
  assert.equal(scanSecretsInText('const k = "AKIAJKLMNOPQRSTUVWXY";', 'a.js').length, 1);
});

test('.env.example et test-*.mjs sont traités comme non-production', () => {
  assert.equal(triageFileFinding({ file: 'apps/backend/.env.example' }).verdict, 'improbable');
  assert.equal(triageFileFinding({ file: 'test-smoke.mjs' }).verdict, 'improbable');
  assert.equal(triageFileFinding({ file: 'config.sample' }).verdict, 'improbable');
  // Un vrai .env reste de la production.
  assert.equal(triageFileFinding({ file: 'apps/backend/.env' }).verdict, 'probable');
});
