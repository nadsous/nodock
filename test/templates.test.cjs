// Tests unitaires hors ligne : moteur de templates YAML.
// Lancer avec `npm test` (compile puis exécute).
const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');

const { parseYaml, parseTemplate, scanTemplatesInText, templateFileTypes } = require('../out/templates.js');

// ---------------------------------------------------------------------------
// Parseur YAML (sous-ensemble)
// ---------------------------------------------------------------------------

test('parseYaml : mappings imbriqués, scalaires et listes inline', () => {
  const doc = parseYaml(`id: NDK-X-001
info:
  name: Mon template
  severity: high
  tags: go, injection
multiline: false
count: 42
`);
  assert.equal(doc.id, 'NDK-X-001');
  assert.equal(doc.info.name, 'Mon template');
  assert.equal(doc.info.tags, 'go, injection', 'le découpage en liste se fait à la validation');
  assert.strictEqual(doc.multiline, false);
  assert.strictEqual(doc.count, 42);
});

test('parseYaml : guillemets simples (regex littérales) et échappement', () => {
  const doc = parseYaml("files: '\\.go$'\nname: 'l''apostrophe'\n");
  assert.equal(doc.files, '\\.go$');
  assert.equal(doc.name, "l'apostrophe");
});

test('parseYaml : liste de mappings (matchers) et commentaires', () => {
  const doc = parseYaml(`# commentaire en tête
matchers:
  - type: regex
    pattern: '\\bexec\\(' # commentaire de fin de ligne
  - type: word
    words: ['a', 'b']
`);
  assert.equal(doc.matchers.length, 2);
  assert.equal(doc.matchers[0].type, 'regex');
  assert.equal(doc.matchers[0].pattern, '\\bexec\\(');
  assert.deepEqual(doc.matchers[1].words, ['a', 'b']);
});

// ---------------------------------------------------------------------------
// Validation de template
// ---------------------------------------------------------------------------

const VALID = `id: NDK-GO-001
info:
  name: exec.Command
  severity: high
  description: Injection de commandes.
  remediation: Utilisez exec.CommandContext.
  reference: https://cwe.mitre.org/data/definitions/78.html
  tags: go
files: '\\.go$'
matchers:
  - type: regex
    pattern: '\\bexec\\.Command\\s*\\('
`;

test('parseTemplate : template valide compilé', () => {
  const t = parseTemplate(VALID, 'test');
  assert.equal(t.id, 'NDK-GO-001');
  assert.equal(t.severity, 'high');
  assert.ok(t.files.test('main.go'));
  assert.ok(!t.files.test('main.py'));
  assert.equal(t.condition, 'or');
  assert.equal(t.multiline, false);
  assert.ok(t.matchers[0].regex.test('exec.Command('));
});

test('parseTemplate : erreurs explicites sur template invalide', () => {
  assert.throws(() => parseTemplate('info:\n  name: x\n', 't'), /champ 'id'/);
  assert.throws(
    () => parseTemplate(VALID.replace('severity: high', 'severity: enormous'), 't'),
    /severity/
  );
  assert.throws(
    () => parseTemplate(VALID.replace(/matchers:[\s\S]*$/, ''), 't'),
    /matcher/
  );
  assert.throws(
    () => parseTemplate(VALID.replace("'\\bexec\\.Command\\s*\\('", "'(*bad'"), 't'),
    /regex invalide/
  );
});

test('parseTemplate : files accepte une extension nue', () => {
  const t = parseTemplate(VALID.replace("files: '\\.go$'", 'files: [go, mod]'), 't');
  assert.ok(t.files.test('x.go'));
  assert.ok(t.files.test('x.mod'));
  assert.ok(!t.files.test('x.py'));
});

// ---------------------------------------------------------------------------
// Application
// ---------------------------------------------------------------------------

test('scanTemplatesInText : finding ligne, commentaires ignorés, exemption', () => {
  const t = parseTemplate(VALID, 'test');
  const vuln = 'package main\n\texec.Command(cmd)\n';
  const findings = scanTemplatesInText('main.go', 'main.go', vuln, [t]);
  assert.equal(findings.length, 1);
  assert.equal(findings[0].line, 2);
  assert.equal(findings[0].kind, 'sast');
  assert.equal(findings[0].id, 'NDK-GO-001');
  assert.match(findings[0].description, /🛡️/);
  assert.equal(findings[0].url, 'https://cwe.mitre.org/data/definitions/78.html');

  const commented = '// exec.Command(cmd)\n';
  assert.equal(scanTemplatesInText('main.go', 'main.go', commented, [t]).length, 0);

  const exempt = parseTemplate(VALID + "exempt: 'CommandContext'\n", 'test');
  const safe = 'out, err := exec.CommandContext(ctx, name)\nexec.Command(cmd)\n';
  // CommandContext est dans la fenêtre des deux lignes : les deux sont exemptées.
  assert.equal(scanTemplatesInText('main.go', 'main.go', safe, [exempt]).length, 0);
});

test('scanTemplatesInText : condition and et matcher word', () => {
  const t = parseTemplate(`id: NDK-X-002
info:
  name: combinaison
  severity: medium
  description: Deux signaux sur la même ligne.
files: '\\.py$'
matchers:
  - type: word
    words: ['subprocess']
  - type: word
    words: ['shell=True']
    ignoreCase: true
condition: and
`, 'test');
  assert.equal(
    scanTemplatesInText('a.py', 'a.py', 'subprocess.call(x, SHELL=TRUE)\n', [t]).length,
    1
  );
  assert.equal(
    scanTemplatesInText('a.py', 'a.py', 'import subprocess\n', [t]).length,
    0,
    'and : un seul signal ne suffit pas'
  );
});

test('scanTemplatesInText : multiline trouve le motif à cheval sur les lignes', () => {
  const t = parseTemplate(`id: NDK-X-003
info:
  name: motif étalé
  severity: low
  description: Motif sur deux lignes.
files: '\\.js$'
multiline: true
matchers:
  - type: regex
    pattern: 'foo\\s*\\(\\s*[^)]*bar'
    flags: s
`, 'test');
  const text = 'foo(\n  baz + bar);\n';
  const findings = scanTemplatesInText('a.js', 'a.js', text, [t]);
  assert.equal(findings.length, 1);
  assert.equal(findings[0].line, 1);
});

test('templateFileTypes : union des cibles', () => {
  const t = parseTemplate(VALID, 'test');
  const re = templateFileTypes([t]);
  assert.ok(re.test('a/b/main.go'));
  assert.ok(!re.test('a/b/main.py'));
  assert.equal(templateFileTypes([]), null);
});

// ---------------------------------------------------------------------------
// Templates embarqués : ils doivent tous être valides et trouver leur cible
// ---------------------------------------------------------------------------

test('templates/ embarqués : tous valides, ids uniques', () => {
  const dir = path.join(__dirname, '..', 'templates');
  const files = fs.readdirSync(dir).filter((f) => /\.ya?ml$/i.test(f));
  assert.ok(files.length >= 15, `au moins 15 templates embarqués, trouvé ${files.length}`);
  const ids = new Set();
  for (const f of files) {
    const t = parseTemplate(fs.readFileSync(path.join(dir, f), 'utf8'), f);
    assert.ok(!ids.has(t.id), `id dupliqué : ${t.id}`);
    ids.add(t.id);
  }
});

test('templates embarqués : chaque langage a au moins une règle qui matche', () => {
  const dir = path.join(__dirname, '..', 'templates');
  const byId = new Map();
  for (const f of fs.readdirSync(dir).filter((f) => /\.ya?ml$/i.test(f))) {
    const t = parseTemplate(fs.readFileSync(path.join(dir, f), 'utf8'), f);
    byId.set(t.id, t);
  }
  const cases = [
    ['NDK-GO-001', 'main.go', '\tcmd := exec.Command(name)\n'],
    ['NDK-GO-003', 'tls.go', '\tInsecureSkipVerify: true,\n'],
    ['NDK-JAVA-001', 'A.java', 'Runtime.getRuntime().exec(cmd);\n'],
    ['NDK-PHP-001', 'a.php', '<?php eval($code); ?>\n'],
    ['NDK-PHP-005', 'a.php', 'unserialize($data);\n'],
    ['NDK-RB-001', 'a.rb', "system('ls ' + dir)\n"],
    ['NDK-CS-002', 'A.cs', 'var f = new BinaryFormatter();\n'],
  ];
  for (const [id, file, text] of cases) {
    const t = byId.get(id);
    assert.ok(t, `template ${id} présent`);
    assert.equal(
      scanTemplatesInText(file, file, text, [t]).length,
      1,
      `${id} doit détecter son motif dans ${file}`
    );
  }
});
