// Tests unitaires hors ligne : export CycloneDX (SBOM).
// Lancer avec `npm test` (compile puis exécute).
const test = require('node:test');
const assert = require('node:assert');

const { toPurl, toCycloneDx } = require('../out/sbom.js');

const dep = (pkg, version, ecosystem, extra = {}) => ({
  kind: 'dependency',
  severity: 'high',
  id: 'CVE-2024-0001',
  title: `${pkg} vulnérable`,
  description: 'détail',
  package: pkg,
  version,
  ecosystem,
  ...extra,
});

test('toPurl : un type de purl par écosystème', () => {
  assert.equal(toPurl({ name: 'lodash', version: '1.0.0', ecosystem: 'npm' }), 'pkg:npm/lodash@1.0.0');
  assert.equal(toPurl({ name: 'requests', version: '2.31.0', ecosystem: 'PyPI' }), 'pkg:pypi/requests@2.31.0');
  assert.equal(
    toPurl({ name: 'org.apache:x', version: '1.0', ecosystem: 'Maven' }),
    'pkg:maven/org.apache/x@1.0'
  );
  assert.equal(
    toPurl({ name: 'guzzlehttp/guzzle', version: '7.8.1', ecosystem: 'Packagist' }),
    'pkg:composer/guzzlehttp/guzzle@7.8.1'
  );
  assert.equal(
    toPurl({ name: 'github.com/x/y', version: '1.2.3', ecosystem: 'Go' }),
    'pkg:golang/github.com/x/y@1.2.3'
  );
  assert.equal(
    toPurl({ name: 'Newtonsoft.Json', version: '13.0.3', ecosystem: 'NuGet' }),
    'pkg:nuget/Newtonsoft.Json@13.0.3'
  );
  assert.equal(toPurl({ name: 'rails', version: '7.1', ecosystem: 'RubyGems' }), 'pkg:gem/rails@7.1');
});

test('affects : le purl porte l\'écosystème RÉEL, jamais npm par défaut (régression)', () => {
  const components = [
    { name: 'requests', version: '2.31.0', ecosystem: 'PyPI' },
    { name: 'guzzlehttp/guzzle', version: '7.8.1', ecosystem: 'Packagist' },
  ];
  const findings = [
    dep('requests', '2.31.0', 'PyPI'),
    dep('guzzlehttp/guzzle', '7.8.1', 'Packagist'),
  ];
  const bom = toCycloneDx(components, findings, { name: 'app', version: '1.0.0' }, '0.7.0-alpha');
  const affects = bom.vulnerabilities.map((v) => v.affects[0].ref);
  assert.ok(affects.includes('pkg:pypi/requests@2.31.0'));
  assert.ok(affects.includes('pkg:composer/guzzlehttp/guzzle@7.8.1'));
  assert.ok(!affects.some((ref) => ref.startsWith('pkg:npm/')), 'aucun purl npm forcé');
  assert.equal(bom.metadata.tools[0].version, '0.7.0-alpha', 'version de l\'outil paramétrée');
});

test('affects : écosystème retrouvé via les composants si le finding ne le porte pas', () => {
  const components = [{ name: 'serde', version: '1.0.0', ecosystem: 'crates.io' }];
  const finding = dep('serde', '1.0.0', undefined);
  delete finding.ecosystem;
  const bom = toCycloneDx(components, [finding]);
  assert.equal(bom.vulnerabilities[0].affects[0].ref, 'pkg:cargo/serde@1.0.0');
});

test('le triage Nodock se traduit en analyse CycloneDX', () => {
  const finding = dep('lodash', '4.17.20', 'npm', {
    triage: { verdict: 'improbable', reasons: ['jamais importé'] },
  });
  const bom = toCycloneDx([], [finding]);
  assert.equal(bom.vulnerabilities[0].analysis.state, 'not_affected');
  assert.equal(bom.vulnerabilities[0].analysis.justification, 'code_not_reachable');
});
