// Tests du triage : atteignabilité, fichiers générés, divergences de versions
// et non-régression sur les règles de conformité trop larges.
const test = require('node:test');
const assert = require('node:assert');

const {
  extractProbe,
  triageDependency,
  triageFileFinding,
  isDistinctiveSymbol,
} = require('../out/triage.js');
const { extractImports, packageOfSpecifier } = require('../out/imports.js');
const { isGeneratedPath, looksMinified, hasGeneratedBanner } = require('../out/generated.js');
const { detectRangeDivergence, detectDuplicateInstalls } = require('../out/divergence.js');
const { scanRgpdInText } = require('../out/rgpd.js');

const evidence = (o = {}) => ({
  packages: new Set(o.packages || []),
  specifiers: new Set(o.specifiers || []),
  // symbolsByPackage : { 'better-auth': ['oidcProvider'] }
  symbolsByPackage: new Map(
    Object.entries(o.symbolsByPackage || {}).map(([k, v]) => [k, new Set(v)])
  ),
  noSources: o.noSources === true,
});

// ---------------------------------------------------------------------------
// Extraction des API vulnérables depuis un avis (cas réel GHSA-pw9m-5jxm-xr6h)
// ---------------------------------------------------------------------------
const BETTER_AUTH_DETAILS = `### Am I affected?

- Their application uses \`better-auth\` and has enabled at least one of: \`oidcProvider()\`
  (imported from \`better-auth/plugins/oidc-provider\`), or \`mcp()\` (imported from
  \`better-auth/plugins/mcp\`).
- Their application has at least one confidential OAuth client with \`client_secret\`.
`;

test('extractProbe relève les API et sous-chemins cités par l\'avis', () => {
  const probe = extractProbe('better-auth', 'OAuth refresh-token replay', BETTER_AUTH_DETAILS);
  assert.ok(probe.symbols.includes('oidcProvider'), 'oidcProvider attendu');
  assert.ok(probe.symbols.includes('mcp'), 'mcp attendu');
  assert.ok(probe.subpaths.includes('better-auth/plugins/mcp'));
  assert.ok(probe.subpaths.includes('better-auth/plugins/oidc-provider'));
  // Terme de protocole, pas une API à chercher dans le code.
  assert.ok(!probe.symbols.includes('client_secret'), 'client_secret est du bruit');
});

test('le paquet importé sans l\'API vulnérable → aucun chemin détecté', () => {
  const probe = extractProbe('better-auth', '', BETTER_AUTH_DETAILS);
  const t = triageDependency(probe, evidence({ packages: ['better-auth'] }), true);
  assert.equal(t.verdict, 'improbable');
  assert.ok(t.reasons.join(' ').includes('Aucune trace'));
});

test('le paquet importé AVEC l\'API vulnérable → exploitable', () => {
  const probe = extractProbe('better-auth', '', BETTER_AUTH_DETAILS);
  const t = triageDependency(
    probe,
    evidence({ packages: ['better-auth'], symbolsByPackage: { 'better-auth': ['oidcProvider'] } }),
    true
  );
  assert.equal(t.verdict, 'probable');
});

test('un sous-chemin importé suffit à conclure à l\'exploitabilité', () => {
  const probe = extractProbe('better-auth', '', BETTER_AUTH_DETAILS);
  const t = triageDependency(
    probe,
    evidence({
      packages: ['better-auth'],
      specifiers: ['better-auth/plugins/mcp'],
    }),
    true
  );
  assert.equal(t.verdict, 'probable');
});

test('paquet jamais importé → improbable, avec la réserve explicite', () => {
  const probe = extractProbe('left-pad', '', '');
  const t = triageDependency(probe, evidence({ packages: ['react'] }), false);
  assert.equal(t.verdict, 'improbable');
  assert.ok(t.reasons.join(' ').includes('transitive'));
  assert.ok(t.reasons.join(' ').includes('build'), 'la limite doit être annoncée');
});

test('sans sources analysables, aucun verdict n\'est asséné', () => {
  const t = triageDependency(extractProbe('x', '', ''), evidence({ noSources: true }), true);
  assert.equal(t.verdict, 'a-verifier');
});

test('avis sans API nommée → à vérifier, jamais improbable', () => {
  const probe = extractProbe('lodash', 'Denial of service', 'No specific API named here.');
  const t = triageDependency(probe, evidence({ packages: ['lodash'] }), true);
  assert.equal(t.verdict, 'a-verifier');
});

test('seul un symbole distinctif peut conclure à l\'exploitabilité', () => {
  assert.ok(isDistinctiveSymbol('oidcProvider'), 'camelCase');
  assert.ok(isDistinctiveSymbol('deviceAuthorization'));
  assert.ok(isDistinctiveSymbol('storeSessionInDatabase'));
  assert.ok(isDistinctiveSymbol('oidc-provider'), 'composé');
  assert.ok(!isDistinctiveSymbol('update'), 'terme courant');
  assert.ok(!isDistinctiveSymbol('token'));
  // Mot courant malgré ses 12 caractères : la longueur n'est pas un critère.
  assert.ok(!isDistinctiveSymbol('organization'));
  assert.ok(!isDistinctiveSymbol('authorization'));
});

test('des termes génériques trouvés dans le code ne valent pas « exploitable »', () => {
  // Cas réel : l'avis ne citait que `update` et `token`, présents dans tout projet.
  const probe = { pkg: 'better-auth', subpaths: [], symbols: ['update', 'token'] };
  const t = triageDependency(
    probe,
    evidence({ packages: ['better-auth'], symbolsByPackage: { 'better-auth': ['update', 'token'] } }),
    true
  );
  assert.equal(t.verdict, 'a-verifier', 'ne doit pas conclure à l\'exploitabilité');
  assert.ok(t.reasons.join(' ').includes('trop courants'));
});

test('un symbole homonyme d\'un autre paquet ne valide pas la CVE', () => {
  // Cas réel Mastore : `deleteMany` est cité par un avis better-auth, mais dans
  // le code il vient de Prisma. Rattaché à prisma, il ne doit rien prouver.
  const probe = { pkg: 'better-auth', subpaths: [], symbols: ['deleteMany'] };
  const t = triageDependency(
    probe,
    evidence({
      packages: ['better-auth', '@prisma/client'],
      symbolsByPackage: { '@prisma/client': ['deleteMany'] },
    }),
    true
  );
  assert.equal(t.verdict, 'improbable', 'le symbole appartient à un autre paquet');
});

test('un sous-chemin conteneur ne suffit pas à conclure', () => {
  // `better-auth/plugins` est importé pour n'importe quel plugin (twoFactor…) :
  // ce n'est pas une preuve d'usage du plugin vulnérable.
  const probe = extractProbe(
    'better-auth',
    '',
    'The flaw is in `better-auth/plugins`, reached via `consumeVerificationValue()`.'
  );
  assert.ok(!probe.subpaths.includes('better-auth/plugins'), 'chemin conteneur exclu');
  assert.ok(probe.symbols.includes('consumeVerificationValue'));

  const t = triageDependency(
    probe,
    evidence({ packages: ['better-auth'], specifiers: ['better-auth/plugins'] }),
    true
  );
  assert.equal(t.verdict, 'improbable');
});

// ---------------------------------------------------------------------------
test('triage par emplacement : test/fixture vs production', () => {
  assert.equal(triageFileFinding({ file: 'src/auth/login.ts' }).verdict, 'probable');
  assert.equal(triageFileFinding({ file: 'src/__tests__/login.test.ts' }).verdict, 'improbable');
  assert.equal(triageFileFinding({ file: 'tests/fixtures/keys.json' }).verdict, 'improbable');
  assert.equal(triageFileFinding({ file: 'docs/guide.md' }).verdict, 'improbable');
  assert.equal(triageFileFinding({ file: 'e2e/checkout.spec.ts' }).verdict, 'improbable');
});

// ---------------------------------------------------------------------------
test('extraction des imports JS et Python', () => {
  const js = extractImports(
    'a.ts',
    `import { auth } from 'better-auth';
     import { mcp } from "better-auth/plugins/mcp";
     const x = require('lodash');
     const y = await import('@scope/pkg/sub');
     import './styles.css';`
  );
  assert.ok(js.packages.has('better-auth'));
  assert.ok(js.packages.has('lodash'));
  assert.ok(js.packages.has('@scope/pkg'));
  assert.ok(js.specifiers.has('better-auth/plugins/mcp'));
  assert.ok(!js.packages.has('./styles.css'), 'les imports relatifs sont exclus');

  const py = extractImports('a.py', 'from django.db import models\nimport requests, numpy as np');
  assert.ok(py.packages.has('django'));
  assert.ok(py.packages.has('requests'));
  assert.ok(py.packages.has('numpy'));
});

test('packageOfSpecifier gère scopes, sous-chemins et builtins', () => {
  assert.equal(packageOfSpecifier('better-auth/plugins/mcp'), 'better-auth');
  assert.equal(packageOfSpecifier('@scope/pkg/sub'), '@scope/pkg');
  assert.equal(packageOfSpecifier('./local'), null);
  assert.equal(packageOfSpecifier('node:fs'), null);
});

// ---------------------------------------------------------------------------
test('les sorties de build sont reconnues comme générées', () => {
  assert.ok(isGeneratedPath('apps/frontend/.next/dev/server/chunks/ssr/021f_yjs.js'));
  assert.ok(isGeneratedPath('packages/ui/dist/index.js'));
  assert.ok(isGeneratedPath('static/app.min.js'));
  assert.ok(isGeneratedPath('build/main.4f3a9b2c.js'));
  assert.ok(!isGeneratedPath('src/components/Button.tsx'));
  assert.ok(!isGeneratedPath('apps/backend/src/lib/auth.ts'));
});

test('le contenu minifié est détecté même hors dossier de build', () => {
  assert.ok(looksMinified('var a=1;'.repeat(1000)));
  assert.ok(!looksMinified('const a = 1;\nconst b = 2;\nconst c = 3;\n'));
  assert.ok(hasGeneratedBanner('// @generated by protoc\nconst x = 1;'));
  assert.ok(hasGeneratedBanner('/* Code generated by tool. DO NOT EDIT. */'));
  assert.ok(!hasGeneratedBanner('// Mon module maison\nconst x = 1;'));
});

// ---------------------------------------------------------------------------
test('divergence de ranges déclarés entre workspaces', () => {
  const findings = detectRangeDivergence([
    { name: 'better-auth', range: '^1.4.18', file: 'apps/backend/package.json', ecosystem: 'npm' },
    { name: 'better-auth', range: '^1.6.1', file: 'apps/frontend/package.json', ecosystem: 'npm' },
    { name: 'react', range: '^19.0.0', file: 'apps/backend/package.json', ecosystem: 'npm' },
    { name: 'react', range: '^19.0.0', file: 'apps/frontend/package.json', ecosystem: 'npm' },
  ]);
  assert.equal(findings.length, 1, 'seul better-auth diverge');
  assert.equal(findings[0].package, 'better-auth');
  assert.ok(findings[0].description.includes('apps/backend/package.json'));
  assert.ok(findings[0].description.includes('apps/frontend/package.json'));
});

test('versions multiples réellement installées (dépendances directes)', () => {
  const deps = [
    { name: 'better-auth', version: '1.6.1', ecosystem: 'npm', file: 'bun.lock' },
    { name: 'better-auth', version: '1.4.18', ecosystem: 'npm', file: 'bun.lock' },
    { name: 'react', version: '19.0.0', ecosystem: 'npm', file: 'bun.lock' },
    // Duplication transitive : banale dans tout arbre npm/bun, non actionnable.
    { name: '@eslint/core', version: '0.17.0', ecosystem: 'npm', file: 'bun.lock' },
    { name: '@eslint/core', version: '1.2.0', ecosystem: 'npm', file: 'bun.lock' },
  ];
  const direct = new Set(['better-auth', 'react']);

  const findings = detectDuplicateInstalls(deps, direct);
  assert.equal(findings.length, 1, 'seules les dépendances directes sont signalées');
  assert.equal(findings[0].package, 'better-auth');
  assert.ok(findings[0].title.includes('1.4.18'));
  assert.ok(findings[0].title.includes('1.6.1'));
});

test('le code généré dans src/ est exclu (client Prisma)', () => {
  assert.ok(isGeneratedPath('apps/backend/src/generated/prisma/internal/prismaNamespace.ts'));
  assert.ok(isGeneratedPath('src/__generated__/schema.ts'));
  assert.ok(isGeneratedPath('apps/backend/prisma/migrations/001_init/migration.sql'));
  assert.ok(!isGeneratedPath('apps/backend/src/lib/auth.ts'));
});

// ---------------------------------------------------------------------------
// Non-régression : les 30 faux positifs remontés par le beta testeur
// ---------------------------------------------------------------------------
test('CMP-009 ne matche plus les arbres de noeuds ni les props React', () => {
  const noise = [
    'const child = node.children[0];',
    'function getChildren(parent) { return parent.childNodes; }',
    'export function Layout({ children }) { return children; }',
    'if (item.child) { walk(item.child); }',
  ].join('\n');
  const found = scanRgpdInText('a.tsx', 'a.tsx', noise).filter((f) => f.id === 'CMP-009');
  assert.equal(found.length, 0, 'aucun signalement attendu sur du code d\'arbre');
});

test('CMP-009 détecte toujours un vrai ciblage enfants', () => {
  for (const real of [
    'const COPPA_COMPLIANT = true;',
    'if (user.age < 13) requireParentalConsent();',
    'const ageGate = true;',
    'kidsMode: false,',
  ]) {
    const found = scanRgpdInText('a.ts', 'a.ts', real).filter((f) => f.id === 'CMP-009');
    assert.equal(found.length, 1, `attendu pour : ${real}`);
  }
});

test('CMP-010 ne matche plus les endpoints de healthcheck', () => {
  const noise = 'app.get("/health", healthCheck);\nconst healthz = () => ok();';
  assert.equal(scanRgpdInText('a.ts', 'a.ts', noise).filter((f) => f.id === 'CMP-010').length, 0);
  const real = 'const medicalRecord = await getPatientData(id);';
  assert.equal(scanRgpdInText('a.ts', 'a.ts', real).filter((f) => f.id === 'CMP-010').length, 1);
});

test('CMP-005 ne matche plus devicePixelRatio', () => {
  const noise = 'const dpr = window.devicePixelRatio;\nconst pixelSize = 4;';
  assert.equal(scanRgpdInText('a.ts', 'a.ts', noise).filter((f) => f.id === 'CMP-005').length, 0);
  const real = 'fbq("track", "PageView");';
  assert.equal(scanRgpdInText('a.ts', 'a.ts', real).filter((f) => f.id === 'CMP-005').length, 1);
});

test('CMP-001 ne matche plus une constante en majuscules préfixée G-', () => {
  const noise = 'const G-CODE = 1;\nconst GRID = "G-LAYOUT";';
  assert.equal(scanRgpdInText('a.ts', 'a.ts', noise).filter((f) => f.id === 'CMP-001').length, 0);
  const real = 'gtag("config", "G-ABCDE12345");';
  assert.equal(scanRgpdInText('a.ts', 'a.ts', real).filter((f) => f.id === 'CMP-001').length, 1);
});
