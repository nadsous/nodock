// Tests unitaires hors ligne : score de sécurité pondéré par le triage.
// Lancer avec `npm test` (compile puis exécute).
const test = require('node:test');
const assert = require('node:assert');

const { computeScore, findingWeight } = require('../out/score.js');

const mk = (severity, verdict) => ({
  kind: 'sast',
  severity,
  title: 'x',
  description: 'y',
  ...(verdict ? { triage: { verdict, reasons: [] } } : {}),
});

test('aucun finding = 100', () => {
  assert.equal(computeScore([]), 100);
});

test('le triage module le poids : probable > à vérifier > improbable', () => {
  const probable = findingWeight(mk('critical', 'probable'));
  const aVerifier = findingWeight(mk('critical', 'a-verifier'));
  const improbable = findingWeight(mk('critical', 'improbable'));
  assert.equal(probable, 25);
  assert.equal(aVerifier, 15);
  assert.equal(improbable, 5);
  assert.ok(probable > aVerifier && aVerifier > improbable);
});

test('sans triage, le poids historique est conservé', () => {
  assert.equal(findingWeight(mk('high')), 10);
  assert.equal(findingWeight(mk('medium')), 4);
  assert.equal(findingWeight(mk('low')), 1);
  assert.equal(findingWeight(mk('info')), 0);
});

test('agrégation et bornes', () => {
  assert.equal(computeScore([mk('critical', 'probable')]), 75);
  assert.equal(computeScore([mk('high', 'improbable')]), 98);
  const many = Array.from({ length: 10 }, () => mk('critical', 'probable'));
  assert.equal(computeScore(many), 0, 'le score ne descend pas sous 0');
});
