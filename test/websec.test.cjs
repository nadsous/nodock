// Vulnérabilités applicatives, infrastructure/CI, et export SBOM.
// Chaque règle a un cas vulnérable ET un cas sain : une règle qui ne sait pas
// se taire est aussi inutile qu'une règle qui ne détecte rien.
const test = require('node:test');
const assert = require('node:assert');

const { scanWebSecInText } = require('../out/websec.js');
const { scanInfraInText } = require('../out/infra.js');
const { toCycloneDx, toPurl } = require('../out/sbom.js');

const ids = (text, file = 'src/app/api/x/route.ts') =>
  scanWebSecInText(file, file, text).map((f) => f.id);
const infraIds = (text, file) => scanInfraInText(file, file, text).map((f) => f.id);

// ---------------------------------------------------------------------------
// Applicatif
// ---------------------------------------------------------------------------
test('SSRF : URL fournie par l\'appelant', () => {
  assert.ok(ids('const r = await fetch(req.body.url);').includes('WEB-SSRF-001'));
  assert.ok(ids('await axios.get(searchParams.get("target"));').includes('WEB-SSRF-001'));
  // Une URL constante ne pose pas de problème.
  assert.ok(!ids('await fetch("https://api.stripe.com/v1/charges");').includes('WEB-SSRF-001'));
});

test('les règles serveur ne s\'appliquent pas à un composant navigateur', () => {
  // Faux positif constaté : un fetch dans un composant "use client" part du
  // navigateur de l'utilisateur, ce n'est pas une SSRF.
  const client = '"use client";\nconst r = await fetch(`/api/x/${params.id}`);';
  assert.deepEqual(ids(client, 'src/components/Page.tsx'), []);

  // Le même code côté serveur reste signalé.
  const server = 'const r = await fetch(req.body.url);';
  assert.ok(ids(server, 'src/app/api/x/route.ts').includes('WEB-SSRF-001'));
});

test('comparer deux champs de mot de passe n\'est pas une attaque temporelle', () => {
  const form = '"use client";\nif (password !== confirmPassword) setError("…");';
  assert.deepEqual(ids(form, 'src/app/compte/reset/page.tsx'), []);
  // Une comparaison de jeton côté serveur reste signalée.
  assert.ok(ids('if (token === expected) grant();').includes('WEB-TIME-001'));
});

test('redirection ouverte', () => {
  assert.ok(ids('return NextResponse.redirect(req.query.next);').includes('WEB-RED-001'));
  assert.ok(!ids('return NextResponse.redirect("/dashboard");').includes('WEB-RED-001'));
});

test('injection NoSQL', () => {
  assert.ok(ids('const u = await User.find({ email: req.body.email });').includes('WEB-NOSQL-001'));
  assert.ok(ids('db.users.find({ $where: "this.a == 1" });').includes('WEB-NOSQL-001'));
  assert.ok(!ids('const u = await User.find({ active: true });').includes('WEB-NOSQL-001'));
});

test('mass assignment : corps de requête diffusé vers la base', () => {
  assert.ok(ids('await prisma.user.create({ data: { ...req.body } });').includes('WEB-MASS-001'));
  assert.ok(ids('await User.updateOne({ _id: id }, { ...request.body });').includes('WEB-MASS-001'));
  // Champs extraits explicitement : c'est la bonne pratique.
  assert.ok(
    !ids('await prisma.user.create({ data: { titre, contenu } });').includes('WEB-MASS-001')
  );
});

test('aléa non cryptographique pour un jeton', () => {
  assert.ok(ids('const token = Math.random().toString(36);').includes('WEB-RAND-001'));
  assert.ok(ids('const otp = Math.random() * 1000000;').includes('WEB-RAND-001'));
  // Un usage non sensible reste permis.
  assert.ok(!ids('const delay = Math.random() * 100;').includes('WEB-RAND-001'));
});

test('JWT : décodage sans vérification', () => {
  assert.ok(ids('const p = jwt.decode(token);').includes('WEB-JWT-001'));
  assert.ok(ids('jwt.verify(t, k, { algorithms: ["none"] });').includes('WEB-JWT-001'));
  assert.ok(!ids('jwt.verify(t, k, { algorithms: ["HS256"] });').includes('WEB-JWT-001'));
});

test('cookie sans httpOnly', () => {
  assert.ok(ids('cookies.set("session", token, { secure: true });').includes('WEB-COOKIE-001'));
  assert.ok(
    !ids('cookies.set("session", token, { httpOnly: true, secure: true });').includes(
      'WEB-COOKIE-001'
    )
  );
});

test('CORS : origine reflétée', () => {
  assert.ok(
    ids('res.setHeader("Access-Control-Allow-Origin", req.headers.origin);').includes(
      'WEB-CORS-001'
    )
  );
  assert.ok(
    !ids('res.setHeader("Access-Control-Allow-Origin", "https://app.exemple.fr");').includes(
      'WEB-CORS-001'
    )
  );
});

test('fuite de détail d\'erreur et de secret en journal', () => {
  assert.ok(ids('return NextResponse.json({ error: err.stack });').includes('WEB-LEAK-001'));
  assert.ok(ids('console.log("token:", token);').includes('WEB-LOG-001'));
  assert.ok(!ids('return NextResponse.json({ error: "Erreur interne" });').includes('WEB-LEAK-001'));
});

test('téléversement : nom de fichier client utilisé pour le chemin', () => {
  assert.ok(ids('await writeFile(join(dir, file.originalname), buf);').includes('WEB-UPLOAD-001'));
  assert.ok(!ids('await writeFile(join(dir, randomUUID()), buf);').includes('WEB-UPLOAD-001'));
});

test('Python : SSRF et SQL formaté', () => {
  const py = (t) => scanWebSecInText('api.py', 'api.py', t).map((f) => f.id);
  assert.ok(py('r = requests.get(request.args.get("url"))').includes('WEB-PY-001'));
  assert.ok(py('cursor.execute(f"SELECT * FROM u WHERE id = {uid}")').includes('WEB-PY-002'));
  assert.ok(!py('cursor.execute("SELECT * FROM u WHERE id = %s", (uid,))').includes('WEB-PY-002'));
});

// ---------------------------------------------------------------------------
// Conteneurs
// ---------------------------------------------------------------------------
test('Dockerfile : root, tag latest, secret, TLS désactivé', () => {
  const bad = `FROM node:latest
ENV API_KEY=sk_live_abcdef123456
RUN curl -k https://example.com/install.sh | sh
CMD ["node", "server.js"]`;
  const found = infraIds(bad, 'Dockerfile');
  assert.ok(found.includes('INF-DOCK-001'), 'aucun USER non privilégié');
  assert.ok(found.includes('INF-DOCK-002'), 'tag latest');
  assert.ok(found.includes('INF-DOCK-003'), 'secret en ENV');
  assert.ok(found.includes('INF-DOCK-004'), 'curl -k');
});

test('Dockerfile correct : aucun reproche', () => {
  const good = `FROM node:22.11.0-alpine@sha256:abc123
RUN adduser --disabled-password --gecos "" app
USER app
CMD ["node", "server.js"]`;
  assert.deepEqual(infraIds(good, 'Dockerfile'), []);
});

test('Compose : privilégié, socket Docker, port de base exposé', () => {
  const bad = `services:
  app:
    privileged: true
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
  db:
    ports:
      - "5432:5432"`;
  const found = infraIds(bad, 'docker-compose.yml');
  assert.ok(found.includes('INF-COMP-001'));
  assert.ok(found.includes('INF-COMP-002'));
  assert.ok(found.includes('INF-COMP-003'));

  const good = `services:
  db:
    ports:
      - "127.0.0.1:5432:5432"`;
  assert.ok(!infraIds(good, 'docker-compose.yml').includes('INF-COMP-003'));
});

// ---------------------------------------------------------------------------
// Intégration continue
// ---------------------------------------------------------------------------
test('GitHub Actions : pull_request_target et action non épinglée', () => {
  const bad = `on:
  pull_request_target:
jobs:
  build:
    permissions: write-all
    steps:
      - uses: tierce/action-douteuse@main
      - run: echo \${{ secrets.NPM_TOKEN }}`;
  const found = infraIds(bad, '.github/workflows/ci.yml');
  assert.ok(found.includes('INF-CI-001'), 'pull_request_target');
  assert.ok(found.includes('INF-CI-002'), 'action épinglée sur une branche');
  assert.ok(found.includes('INF-CI-003'), 'permissions write-all');
  assert.ok(found.includes('INF-CI-004'), 'secret interpolé dans run');
});

test('workflow correct : aucun reproche', () => {
  const good = `on:
  pull_request:
jobs:
  build:
    permissions:
      contents: read
    steps:
      - uses: actions/checkout@v4
      - uses: tierce/action@a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0
        env:
          TOKEN: \${{ secrets.NPM_TOKEN }}`;
  assert.deepEqual(infraIds(good, '.github/workflows/ci.yml'), []);
});

// ---------------------------------------------------------------------------
// SBOM
// ---------------------------------------------------------------------------
test('purl selon l\'écosystème', () => {
  assert.equal(toPurl({ name: 'lodash', version: '4.17.21', ecosystem: 'npm' }), 'pkg:npm/lodash@4.17.21');
  assert.equal(
    toPurl({ name: '@scope/pkg', version: '1.0.0', ecosystem: 'npm' }),
    'pkg:npm/@scope%2Fpkg@1.0.0'
  );
  assert.equal(toPurl({ name: 'django', version: '5.0', ecosystem: 'PyPI' }), 'pkg:pypi/django@5.0');
  assert.equal(toPurl({ name: 'serde', version: '1.0', ecosystem: 'crates.io' }), 'pkg:cargo/serde@1.0');
  assert.equal(
    toPurl({ name: 'org.apache:commons', version: '1.0', ecosystem: 'Maven' }),
    'pkg:maven/org.apache/commons@1.0'
  );
});

test('CycloneDX : composants dédupliqués et triage traduit', () => {
  const components = [
    { name: 'lodash', version: '4.17.20', ecosystem: 'npm' },
    { name: 'lodash', version: '4.17.20', ecosystem: 'npm' },
    { name: 'react', version: '19.0.0', ecosystem: 'npm' },
  ];
  const findings = [
    {
      kind: 'dependency',
      severity: 'high',
      id: 'CVE-2021-23337',
      title: 'Command Injection in lodash',
      description: '',
      package: 'lodash',
      version: '4.17.20',
      fixedVersion: '4.17.21',
      cvss: 'CVSS 7.2',
      url: 'https://nvd.nist.gov/vuln/detail/CVE-2021-23337',
      triage: { verdict: 'improbable', reasons: ['Aucune trace de l\'API vulnérable.'] },
    },
    { kind: 'secret', severity: 'critical', id: 'AWS', title: '', description: '' },
  ];

  const bom = toCycloneDx(components, findings, { name: 'demo', version: '1.0.0' });
  assert.equal(bom.bomFormat, 'CycloneDX');
  assert.equal(bom.specVersion, '1.5');
  assert.equal(bom.components.length, 2, 'doublon éliminé');
  assert.equal(bom.vulnerabilities.length, 1, 'seules les vulns de dépendances');

  const v = bom.vulnerabilities[0];
  assert.equal(v.analysis.state, 'not_affected', 'le triage Nodock devient un état CycloneDX');
  assert.equal(v.analysis.justification, 'code_not_reachable');
  assert.equal(v.ratings[0].score, 7.2);
  assert.ok(v.recommendation.includes('4.17.21'));
});

test('CycloneDX : un triage « exploitable » se traduit en exploitable', () => {
  const bom = toCycloneDx(
    [{ name: 'x', version: '1.0.0', ecosystem: 'npm' }],
    [
      {
        kind: 'dependency',
        severity: 'high',
        id: 'CVE-1',
        title: 't',
        description: '',
        package: 'x',
        version: '1.0.0',
        triage: { verdict: 'probable', reasons: ['API présente.'] },
      },
    ]
  );
  assert.equal(bom.vulnerabilities[0].analysis.state, 'exploitable');
  assert.equal(bom.vulnerabilities[0].analysis.justification, undefined);
});

// ---------------------------------------------------------------------------
// FastAPI / Starlette
// ---------------------------------------------------------------------------
const py = (t) => scanWebSecInText('app/main.py', 'app/main.py', t).map((f) => f.id);

test('FastAPI : CORS ouvert à toutes les origines', () => {
  assert.ok(py('    allow_origins=["*"],').includes('WEB-PY-003'));
  assert.ok(py('    allow_origin_regex=".*",').includes('WEB-PY-003'));
  assert.ok(
    !py('    allow_origins=["https://app.exemple.fr"],').includes('WEB-PY-003'),
    'une liste blanche explicite est la bonne pratique'
  );
});

test('FastAPI : JWT décodé sans vérifier la signature', () => {
  assert.ok(
    py('claims = jwt.decode(token, key="", options={"verify_signature": False})').includes(
      'WEB-PY-004'
    )
  );
  assert.ok(py('data = jwt.get_unverified_claims(token)').includes('WEB-PY-004'));
  assert.ok(
    !py('claims = jwt.decode(token, SECRET, algorithms=["HS256"])').includes('WEB-PY-004'),
    'un décodage vérifié ne mérite aucun reproche'
  );
});

test('FastAPI : SQLAlchemy text() assemblé par formatage', () => {
  assert.ok(py('rows = await session.execute(text(f"SELECT * FROM u WHERE id = {uid}"))').includes('WEB-PY-005'));
  assert.ok(py('rows = session.execute(text("SELECT * FROM u WHERE id = " + uid))').includes('WEB-PY-005'));
  assert.ok(
    !py('rows = await session.execute(text("SELECT * FROM u WHERE id = :id"), {"id": uid})').includes(
      'WEB-PY-005'
    ),
    'un paramètre lié est la forme correcte'
  );
});

test('FastAPI : chemin de fichier interpolé', () => {
  assert.ok(py('return FileResponse(f"uploads/{nom}")').includes('WEB-PY-006'));
  assert.ok(py('with open(f"/data/{nom}.json") as fh:').includes('WEB-PY-006'));
  assert.ok(
    !py('return FileResponse(RACINE / str(uuid4()))').includes('WEB-PY-006'),
    'un nom généré côté serveur ne sort pas du dossier'
  );
});

test('FastAPI : HTML assemblé par interpolation', () => {
  assert.ok(py('return HTMLResponse(f"<h1>Bonjour {nom}</h1>")').includes('WEB-PY-007'));
  assert.ok(
    !py('return templates.TemplateResponse("accueil.html", {"request": request, "nom": nom})').includes(
      'WEB-PY-007'
    ),
    'un template échappe automatiquement'
  );
});

test('FastAPI : échappement de template désactivé', () => {
  assert.ok(py('env = Environment(loader=loader, autoescape=False)').includes('WEB-PY-008'));
  assert.ok(!py('env = Environment(loader=loader, autoescape=True)').includes('WEB-PY-008'));
});

test('FastAPI : SSRF via httpx', () => {
  assert.ok(py('r = await client.get(request.args.get("url"))').includes('WEB-PY-001'));
  assert.ok(
    !py('r = await client.get("https://api.stripe.com/v1/charges")').includes('WEB-PY-001'),
    'une URL constante ne pose pas de problème'
  );
});

test('les règles Python ne s\'appliquent pas aux fichiers JS', () => {
  assert.deepEqual(
    ids('const cors = { allow_origins: ["*"] };').filter((id) => id.startsWith('WEB-PY-')),
    []
  );
});
