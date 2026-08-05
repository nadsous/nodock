// Normes de codage : activation conditionnée à la version, et exemptions SAST
// contextuelles (JSON-LD, innerHTML vidé).
const test = require('node:test');
const assert = require('node:assert');

const {
  applicableRules,
  scanStandardsInText,
  aggregateStandards,
} = require('../out/standards.js');
const { scanCodeInText } = require('../out/sast.js');
const { aggregateCompliance, scanRgpdInText } = require('../out/rgpd.js');

const rulesFor = (pkgs) => applicableRules(new Map(Object.entries(pkgs)));
const ids = (findings) => findings.map((f) => f.id);

test('une règle liée à un framework absent n\'est jamais activée', () => {
  const rules = rulesFor({});
  assert.ok(!rules.some((r) => r.pkg), 'aucune règle de framework sans framework installé');
  // Les règles de plateforme (Node, Python) restent actives.
  assert.ok(rules.some((r) => r.id === 'STD-NODE-001'));
  assert.ok(rules.some((r) => r.id === 'STD-PY-001'));
});

test('la version décide : React 17 vs 19', () => {
  const r17 = ids(rulesFor({ react: '17.0.2' }));
  assert.ok(!r17.includes('STD-REACT-001'), 'ReactDOM.render est normal en React 17');
  assert.ok(!r17.includes('STD-REACT-002'));

  const r19 = ids(rulesFor({ react: '19.0.0' }));
  assert.ok(r19.includes('STD-REACT-001'), 'supprimé en React 19');
  assert.ok(r19.includes('STD-REACT-002'), 'propTypes ignorés en React 19');
  assert.ok(r19.includes('STD-REACT-004'));

  const r18 = ids(rulesFor({ react: '18.3.1' }));
  assert.ok(r18.includes('STD-REACT-001'), 'déprécié dès React 18');
  assert.ok(!r18.includes('STD-REACT-002'), 'propTypes encore valides en React 18');
});

test('Next.js : les règles suivent la majeure installée', () => {
  assert.ok(!ids(rulesFor({ next: '12.3.4' })).includes('STD-NEXT-001'));
  assert.ok(ids(rulesFor({ next: '13.5.0' })).includes('STD-NEXT-001'));
  assert.ok(ids(rulesFor({ next: '16.2.3' })).includes('STD-NEXT-002'));
});

test('détection effective avec correctif et justification de version', () => {
  const rules = rulesFor({ react: '19.0.0' });
  const found = scanStandardsInText(
    'src/main.tsx',
    'src/main.tsx',
    'ReactDOM.render(<App />, document.getElementById("root"));',
    rules
  );
  assert.equal(found.length, 1);
  assert.equal(found[0].kind, 'standards');
  assert.ok(found[0].description.includes('createRoot'), 'le correctif est donné');
  assert.ok(found[0].description.includes('react ≥ 18'), 'la raison de l\'activation est dite');
});

test('importer react-dom ne déclenche pas l\'alerte ReactDOM.render', () => {
  const rules = rulesFor({ react: '19.2.4' });
  // Faux positif constaté sur workyt-next : createPortal reste valide en React 19.
  const ok = 'import { createPortal } from "react-dom";';
  assert.equal(scanStandardsInText('a.tsx', 'a.tsx', ok, rules).length, 0);
  // Le vrai appel reste détecté.
  assert.equal(
    scanStandardsInText('a.tsx', 'a.tsx', 'ReactDOM.render(<App />, el);', rules).length,
    1
  );
});

test('une migration devient un seul finding groupé', () => {
  // 75 forwardRef shadcn/ui = une tâche de codemod, pas 75 problèmes.
  const many = Array.from({ length: 75 }, (_, i) => ({
    kind: 'standards',
    severity: 'low',
    id: 'STD-REACT-003',
    title: '',
    description: 'x',
    file: `src/components/ui/C${i}.tsx`,
    line: 11,
  }));
  const out = aggregateStandards(many);
  assert.equal(out.length, 1);
  assert.ok(out[0].title.includes('75 occurrence'));
  assert.ok(out[0].description.includes('Migration groupée'));
  assert.ok(out[0].description.includes('… et 67 autre(s)'));
});

test('les règles hors migration restent signalées une par une', () => {
  const two = ['a.js', 'b.js'].map((file) => ({
    kind: 'standards',
    severity: 'high',
    id: 'STD-NODE-001',
    title: '',
    description: 'x',
    file,
    line: 1,
  }));
  assert.equal(aggregateStandards(two).length, 2, 'chaque new Buffer() se corrige sur place');
});

test('les règles de plateforme ne dépendent d\'aucun paquet', () => {
  const rules = rulesFor({});
  assert.equal(scanStandardsInText('a.js', 'a.js', 'const b = new Buffer(10);', rules).length, 1);
  assert.equal(
    scanStandardsInText('a.py', 'a.py', 'now = datetime.utcnow()', rules).length,
    1
  );
});

// ---------------------------------------------------------------------------
// Le bruit signalé sur workyt-next : 29 dangerouslySetInnerHTML de JSON-LD
// ---------------------------------------------------------------------------
test('dangerouslySetInnerHTML avec JSON.stringify n\'est pas une injection', () => {
  const jsonLd =
    '<script type="application/ld+json" dangerouslySetInnerHTML={{ __html: JSON.stringify(aboutLd) }} />';
  assert.equal(scanCodeInText('page.tsx', 'page.tsx', jsonLd).length, 0);

  // Le motif JSX réparti sur plusieurs lignes doit aussi être disculpé.
  const multiline = [
    '<script',
    '  type="application/ld+json"',
    '  dangerouslySetInnerHTML={{',
    '    __html: JSON.stringify(schema),',
    '  }}',
    '/>',
  ].join('\n');
  assert.equal(
    scanCodeInText('p.tsx', 'p.tsx', multiline).filter((f) => f.id === 'NDK-JS-004').length,
    0
  );
});

test('dangerouslySetInnerHTML sur une donnée brute reste signalé', () => {
  const risky = '<div dangerouslySetInnerHTML={{ __html: article.content }} />';
  const found = scanCodeInText('p.tsx', 'p.tsx', risky).filter((f) => f.id === 'NDK-JS-004');
  assert.equal(found.length, 1);
});

test('un contenu sanitizé est accepté', () => {
  const safe = '<div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(html) }} />';
  assert.equal(scanCodeInText('p.tsx', 'p.tsx', safe).filter((f) => f.id === 'NDK-JS-004').length, 0);
});

test('innerHTML vidé ou constant n\'est pas un risque', () => {
  assert.equal(scanCodeInText('a.js', 'a.js', "el.innerHTML = '';").length, 0);
  assert.equal(scanCodeInText('a.js', 'a.js', 'el.innerHTML = "";').length, 0);
  // Une variable reste signalée.
  assert.equal(scanCodeInText('a.js', 'a.js', 'el.innerHTML = userInput;').length, 1);
});

// ---------------------------------------------------------------------------
test('la conformité est agrégée au niveau du projet', () => {
  const perFile = [
    { kind: 'rgpd', severity: 'medium', id: 'CMP-003', title: '', description: 'x', file: 'a.tsx', line: 5 },
    { kind: 'rgpd', severity: 'medium', id: 'CMP-003', title: '', description: 'x', file: 'b.tsx', line: 12 },
    { kind: 'rgpd', severity: 'medium', id: 'CMP-003', title: '', description: 'x', file: 'c.tsx', line: 3 },
    { kind: 'rgpd', severity: 'high', id: 'CMP-001', title: '', description: 'y', file: 'd.tsx', line: 1 },
  ];
  const out = aggregateCompliance(perFile);
  assert.equal(out.length, 2, 'une obligation légale = un finding');

  const cmp003 = out.find((f) => f.id === 'CMP-003');
  assert.ok(cmp003.description.includes('a.tsx:5'), 'les emplacements sont conservés');
  assert.ok(cmp003.description.includes('c.tsx:3'));
  assert.ok(cmp003.description.includes('Où (3)'));
});

test('les consignes de conformité sont concrètes', () => {
  const out = aggregateCompliance(
    scanRgpdInText('a.tsx', 'a.tsx', 'localStorage.setItem("uid", id);')
  );
  const d = out[0].description;
  assert.ok(d.includes('Ce que vous devez faire'), 'des actions techniques');
  assert.ok(d.includes('À ajouter dans vos mentions légales'), 'du texte à coller');
  assert.ok(d.includes('httpOnly'), 'un conseil précis, pas une généralité');
});

test('le Markdown n\'est plus analysé pour la conformité', () => {
  // Un guide d'intégration citant des schémas médicaux n'est pas un traitement.
  assert.equal(scanRgpdInText('docs/schema.md', 'docs/schema.md', 'MedicalClinic patient').length, 0);
});
