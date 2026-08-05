// Tests unitaires hors ligne : parseurs de lockfiles, détection de secrets, CVSS.
// Lancer avec `npm test` (compile puis exécute).
const test = require('node:test');
const assert = require('node:assert');

const P = require('../out/parsers.js');
const { scanSecretsInText } = require('../out/secrets.js');
const { scanCodeInText } = require('../out/sast.js');
const { cvss3BaseScore } = require('../out/cvss.js');

const find = (deps, name) => deps.find((d) => d.name === name);

// ---------------------------------------------------------------------------
test('package-lock v3 : versions installées, pas les ranges', () => {
  const lock = {
    lockfileVersion: 3,
    packages: {
      '': { name: 'app' },
      'node_modules/lodash': { version: '4.17.21' },
      'node_modules/@scope/pkg': { version: '2.0.1' },
      'node_modules/a/node_modules/nested': { version: '0.1.0' },
      'packages/local-app': { link: true, resolved: 'packages/local-app' },
    },
  };
  const deps = P.parsePackageLock(lock, 'package-lock.json');
  assert.equal(find(deps, 'lodash').version, '4.17.21');
  assert.equal(find(deps, '@scope/pkg').version, '2.0.1');
  assert.equal(find(deps, 'nested').version, '0.1.0');
  assert.equal(deps.length, 3, 'les workspaces locaux ne sont pas des dépendances publiées');
});

test('package-lock v1 : arbre imbriqué', () => {
  const lock = {
    lockfileVersion: 1,
    dependencies: {
      minimist: { version: '1.2.5', dependencies: { deep: { version: '0.0.1' } } },
    },
  };
  const deps = P.parsePackageLock(lock, 'package-lock.json');
  assert.equal(find(deps, 'minimist').version, '1.2.5');
  assert.equal(find(deps, 'deep').version, '0.0.1');
});

test('yarn.lock v1 et Berry', () => {
  const v1 = `# yarn lockfile v1

lodash@^4.17.20:
  version "4.17.21"
  resolved "https://registry.yarnpkg.com/lodash/-/lodash-4.17.21.tgz"

"@babel/core@^7.0.0":
  version "7.24.0"
`;
  const d1 = P.parseYarnLock(v1, 'yarn.lock');
  assert.equal(find(d1, 'lodash').version, '4.17.21');
  assert.equal(find(d1, '@babel/core').version, '7.24.0');

  const berry = `__metadata:
  version: 6

"lodash@npm:^4.17.20":
  version: 4.17.21
  resolution: "lodash@npm:4.17.21"
`;
  assert.equal(find(P.parseYarnLock(berry, 'yarn.lock'), 'lodash').version, '4.17.21');
});

test('pnpm-lock : formats v5, v6 et v9', () => {
  const text = `lockfileVersion: '6.0'

packages:

  /lodash/4.17.21:
    resolution: {integrity: sha512-x}

  /@babel/core@7.24.0:
    resolution: {integrity: sha512-y}

  react@18.2.0:
    resolution: {integrity: sha512-z}

  /vue@3.4.0(typescript@5.4.0):
    resolution: {integrity: sha512-w}
`;
  const deps = P.parsePnpmLock(text, 'pnpm-lock.yaml');
  assert.equal(find(deps, 'lodash').version, '4.17.21');
  assert.equal(find(deps, '@babel/core').version, '7.24.0');
  assert.equal(find(deps, 'react').version, '18.2.0');
  assert.equal(find(deps, 'vue').version, '3.4.0', 'les peers entre parenthèses sont ignorés');
});

test('bun.lock : versions installées, workspaces et JSONC tolérés', () => {
  // JSONC avec virgules traînantes : bun.lock n'est pas du JSON strict.
  const lock = `{
  "lockfileVersion": 1,
  "workspaces": {
    "apps/backend": {
      "dependencies": {
        "better-auth": "^1.4.18",
      },
    },
    "apps/frontend": {
      "dependencies": {
        "better-auth": "^1.6.1",
      },
    },
  },
  "packages": {
    "better-auth": ["better-auth@1.6.1", "", { "dependencies": {} }, "sha512-x"],
    "@scope/pkg": ["@scope/pkg@2.0.1", "", {}, "sha512-y"],
    "@mastore/backend": ["@mastore/backend@workspace:apps/backend"],
    "parent/nested": ["nested@0.3.0", "", {}, "sha512-z"],
  }
}`;
  const deps = P.parseBunLock(lock, 'bun.lock');
  assert.equal(find(deps, 'better-auth').version, '1.6.1', 'la version installée, pas le range');
  assert.equal(find(deps, '@scope/pkg').version, '2.0.1');
  assert.equal(find(deps, 'nested').version, '0.3.0', 'le nom vient du spécificateur');
  assert.equal(find(deps, '@mastore/backend'), undefined, 'workspace local exclu');
  // Les ranges de la section workspaces ne doivent pas être pris pour des versions.
  assert.equal(deps.filter((d) => d.version === '1.4.18').length, 0);
});

test('Cargo.lock et poetry.lock ([[package]])', () => {
  const cargo = `
[[package]]
name = "serde"
version = "1.0.197"

[[package]]
name = "tokio"
version = "1.36.0"
`;
  const deps = P.parseTomlPackageBlocks(cargo, 'Cargo.lock', 'crates.io');
  assert.equal(deps.length, 2);
  assert.equal(find(deps, 'tokio').version, '1.36.0');
  assert.equal(find(deps, 'tokio').ecosystem, 'crates.io');
});

test('package.json : version déduite du range, marquée imprécise', () => {
  const deps = P.parsePackageJson(
    {
      dependencies: { lodash: '^4.17.20', local: 'workspace:*', star: '*' },
      devDependencies: { typescript: '~5.4.0' },
    },
    'package.json'
  );
  assert.equal(find(deps, 'lodash').version, '4.17.20');
  assert.equal(find(deps, 'lodash').imprecise, true);
  assert.equal(find(deps, 'typescript').version, '5.4.0');
  assert.equal(find(deps, 'local'), undefined, 'workspace: ignoré');
  assert.equal(find(deps, 'star'), undefined, 'range sans version ignoré');
});

test('dedupe : la version issue du lockfile gagne sur celle du manifeste', () => {
  const deduped = P.dedupeDeps([
    { name: 'lodash', version: '4.17.21', ecosystem: 'npm', file: 'package.json', imprecise: true },
    { name: 'lodash', version: '4.17.21', ecosystem: 'npm', file: 'package-lock.json' },
  ]);
  assert.equal(deduped.length, 1);
  assert.equal(deduped[0].imprecise, undefined);
  assert.equal(deduped[0].file, 'package-lock.json');
});

// ---------------------------------------------------------------------------
test('secrets : un match ne masque pas ceux des lignes suivantes (bug lastIndex)', () => {
  // Le secret de la ligne 1 matche à un offset élevé ; avec une regex /g partagée,
  // l'ancien code reprenait la ligne 2 à cet offset et ratait le secret.
  const text = [
    'const padding = "..............................."; const a = "AKIAIOSFODNN7ABCDEFG";',
    'const b = "AKIAJKLMNOPQRSTUVWXY";',
    'const c = "AKIAZZZZZZZZZZZZZZZZ";',
  ].join('\n');

  const lines = scanSecretsInText(text, 'a.js')
    .filter((f) => f.id === 'AWS Access Key')
    .map((f) => f.line);

  assert.deepEqual(lines, [1, 2, 3], 'les 3 clés AWS doivent être détectées');
});

test('secrets : plusieurs secrets sur une même ligne', () => {
  const text = 'a="AKIAIOSFODNN7ABCDEFG"; b="AKIAJKLMNOPQRSTUVWXY";';
  const found = scanSecretsInText(text, 'a.js').filter((f) => f.id === 'AWS Access Key');
  assert.equal(found.length, 2);
});

test('secrets : la valeur est masquée dans le rapport', () => {
  const found = scanSecretsInText('key = "AKIAIOSFODNN7ABCDEFG"', 'a.js');
  const title = found[0].title;
  assert.ok(!title.includes('AKIAIOSFODNN7ABCDEFG'), 'le secret ne doit pas fuiter en clair');
  assert.ok(title.includes('*'));
});

test('secrets : les placeholders ne déclenchent que les règles heuristiques', () => {
  const placeholder = scanSecretsInText('api_key = "your_api_key_here_placeholder"', '.env');
  assert.equal(placeholder.length, 0, 'placeholder évident ignoré');

  const real = scanSecretsInText('api_key = "Zx8Kq2Lm9Pw4Rt7Yv1Bn6Hs3"', '.env');
  assert.equal(real.length, 1);
});

// ---------------------------------------------------------------------------
test('SAST : le code commenté est ignoré', () => {
  const text = ['// eval(userInput);', 'eval(userInput);'].join('\n');
  const found = scanCodeInText('a.js', 'a.js', text).filter((f) => f.id === 'NDK-JS-001');
  assert.equal(found.length, 1);
  assert.equal(found[0].line, 2);
});

test('SAST : subprocess.exec ne déclenche pas la règle eval de Python', () => {
  const found = scanCodeInText('a.py', 'a.py', 'proc.exec("ls")');
  assert.equal(found.filter((f) => f.id === 'NDK-PY-001').length, 0);
  assert.equal(scanCodeInText('a.py', 'a.py', 'exec("ls")').length, 1);
});

// ---------------------------------------------------------------------------
test('CVSS v3 : scores de référence', () => {
  // CVE-2020-28500 (ReDoS lodash) — score officiel 5.3
  assert.equal(cvss3BaseScore('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L'), 5.3);
  // Log4Shell — 10.0, scope changed
  assert.equal(cvss3BaseScore('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H'), 10);
  // Impact nul → 0
  assert.equal(cvss3BaseScore('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N'), 0);
  // Vecteur illisible → null (on retombe sur la sévérité déclarée)
  assert.equal(cvss3BaseScore('CVSS:4.0/AV:N/AC:L'), null);
});
