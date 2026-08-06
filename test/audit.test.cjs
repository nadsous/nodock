// Audit de posture : ce qui MANQUE. Chaque test reproduit une question qu'un
// auditeur pose réellement en ouvrant un projet.
const test = require('node:test');
const assert = require('node:assert');

const { collectAuditSignals, auditFindings, emptySignals } = require('../out/audit.js');

/** Construit les signaux à partir d'une liste de fichiers simulés. */
function signalsFrom(files) {
  const s = emptySignals();
  for (const [file, text] of Object.entries(files)) {
    collectAuditSignals(file, file, text, s);
  }
  return s;
}

const byId = (findings, id) => findings.find((f) => f.id === id);

const ROUTE_DB_NO_AUTH = `
export async function GET(request) {
  const { searchParams } = new URL(request.url);
  return Response.json(await prisma.user.findMany({ where: { id: searchParams.get('id') } }));
}`;

const ROUTE_WITH_AUTH = `
import { getServerSession } from 'next-auth';
export async function GET(request) {
  const session = await getServerSession();
  if (!session) return new Response('Unauthorized', { status: 401 });
  return Response.json(await prisma.post.findMany());
}`;

// ---------------------------------------------------------------------------
test('recense les routes de chaque framework', () => {
  const s = signalsFrom({
    'src/app/api/users/route.ts': ROUTE_DB_NO_AUTH,
    'src/pages/api/legacy.ts': 'export default function handler(req, res) { res.json({}); }',
    'src/users/users.controller.ts': '@Controller("users") export class UsersController {}',
    'server/routes.js': 'router.post("/items", (req, res) => res.json({}));',
    'src/components/Button.tsx': 'export const Button = () => <button />;',
  });
  assert.equal(s.routes.length, 4, 'le composant React n\'est pas une route');
});

test('une route sans vérification de session et touchant la base est signalée', () => {
  const s = signalsFrom({ 'src/app/api/users/route.ts': ROUTE_DB_NO_AUTH });
  const f = byId(auditFindings(s), 'NDK-AUD-003');
  assert.ok(f, 'constat attendu');
  assert.equal(f.severity, 'high');
  assert.ok(f.description.includes('src/app/api/users/route.ts'));
  assert.ok(f.description.includes('autorisation'), 'la distinction authn/authz est rappelée');
});

test('une route protégée ne déclenche rien', () => {
  const s = signalsFrom({ 'src/app/api/posts/route.ts': ROUTE_WITH_AUTH });
  assert.equal(byId(auditFindings(s), 'NDK-AUD-003'), undefined);
});

test('entrée utilisateur menée jusqu\'à la base sans validation', () => {
  const s = signalsFrom({ 'src/app/api/search/route.ts': ROUTE_DB_NO_AUTH });
  const f = byId(auditFindings(s), 'NDK-AUD-004');
  assert.ok(f);
  assert.ok(f.description.includes('mass assignment'));
});

test('une route validée par un schéma n\'est pas signalée', () => {
  const validated = `
    import { z } from 'zod';
    const schema = z.object({ id: z.string().uuid() });
    export async function POST(request) {
      const body = schema.parse(await request.json());
      return Response.json(await prisma.user.findUnique({ where: { id: body.id } }));
    }`;
  const s = signalsFrom({ 'src/app/api/u/route.ts': validated });
  assert.equal(byId(auditFindings(s), 'NDK-AUD-004'), undefined);
  assert.equal(byId(auditFindings(s), 'NDK-AUD-007'), undefined);
});

test('une garde manuelle vaut validation', () => {
  // Constaté sur un projet réel : isValidObjectId est une vraie validation.
  const manual = `
    export async function POST(req) {
      const body = await req.json();
      const ids = body.ids.filter((id) => mongoose.isValidObjectId(id)).slice(0, 100);
      return Response.json(await User.find({ _id: { $in: ids } }));
    }`;
  const s = signalsFrom({ 'src/app/api/users/batch/route.ts': manual });
  assert.equal(byId(auditFindings(s), 'NDK-AUD-004'), undefined);
});

test('une route qui ne lit aucune entrée n\'est pas reprochée', () => {
  // Faux positif constaté : `params:` dans un objet quelconque suffisait.
  const noInput = `
    import authMiddleware from '@/middlewares/authMiddleware';
    export async function GET(req) {
      const user = await authMiddleware(req);
      if (!(await hasPermission(user.role, 'role.manage'))) return forbidden();
      const roles = await Role.find().sort({ priority: -1 }).lean();
      return NextResponse.json({ roles, params: { cached: true } });
    }`;
  const s = signalsFrom({ 'src/app/api/admin/roles/route.ts': noInput });
  assert.equal(byId(auditFindings(s), 'NDK-AUD-004'), undefined, 'aucune entrée lue');
  assert.equal(byId(auditFindings(s), 'NDK-AUD-003'), undefined, 'authMiddleware reconnu');
});

// ---------------------------------------------------------------------------
test('routes d\'authentification sans limitation de débit', () => {
  const s = signalsFrom({
    'src/app/api/auth/login/route.ts': 'export async function POST(req) { return Response.json({}); }',
  });
  const f = byId(auditFindings(s), 'NDK-AUD-005');
  assert.ok(f);
  assert.equal(f.severity, 'high');
  assert.ok(f.description.includes('bourrage'), 'le risque concret est nommé');
});

test('une limitation de débit ailleurs dans le projet suffit', () => {
  const s = signalsFrom({
    'src/app/api/auth/login/route.ts': 'export async function POST(req) { return Response.json({}); }',
    'src/middleware.ts': 'import { Ratelimit } from "@upstash/ratelimit";',
  });
  assert.equal(byId(auditFindings(s), 'NDK-AUD-005'), undefined);
});

test('absence d\'en-têtes de sécurité', () => {
  const s = signalsFrom({ 'src/app/api/a/route.ts': ROUTE_WITH_AUTH });
  assert.ok(byId(auditFindings(s), 'NDK-AUD-006'));

  const withHeaders = signalsFrom({
    'src/app/api/a/route.ts': ROUTE_WITH_AUTH,
    'next.config.mjs': 'headers: async () => [{ headers: [{ key: "Content-Security-Policy", value: "..." }] }]',
  });
  assert.equal(byId(auditFindings(withHeaders), 'NDK-AUD-006'), undefined);
});

// ---------------------------------------------------------------------------
test('.env non couvert par .gitignore : critique', () => {
  const s = signalsFrom({
    '.env': 'OPENAI_API_KEY=sk-reel',
    '.gitignore': 'node_modules/\n.next/\n',
  });
  const f = byId(auditFindings(s), 'NDK-AUD-001');
  assert.ok(f);
  assert.equal(f.severity, 'critical');
  assert.ok(f.description.includes('historique'), 'le fait qu\'un secret reste dans Git est dit');
});

test('.env correctement ignoré : aucun constat', () => {
  for (const pattern of ['.env', '.env*', '*.env']) {
    const s = signalsFrom({ '.env': 'X=1', '.gitignore': `node_modules/\n${pattern}\n` });
    assert.equal(byId(auditFindings(s), 'NDK-AUD-001'), undefined, `motif ${pattern}`);
  }
});

test('.env.example n\'est pas un secret', () => {
  const s = signalsFrom({ '.env.example': 'API_KEY=', '.gitignore': 'node_modules/' });
  assert.equal(byId(auditFindings(s), 'NDK-AUD-001'), undefined);
});

// ---------------------------------------------------------------------------
test('la carte de surface est informative, pas une alerte', () => {
  const s = signalsFrom({
    'src/app/api/a/route.ts': ROUTE_WITH_AUTH,
    'src/app/api/b/route.ts': ROUTE_DB_NO_AUTH,
  });
  const map = byId(auditFindings(s), 'NDK-AUD-002');
  assert.equal(map.severity, 'info', 'ne doit pas gonfler le compte de problèmes');
  assert.ok(map.title.includes('2 route'));
});

test('un projet sans route ne produit que les constats de secrets', () => {
  const s = signalsFrom({ 'src/lib/utils.ts': 'export const add = (a, b) => a + b;' });
  assert.equal(auditFindings(s).length, 0, 'pas de route, pas de reproche sur les en-têtes');
});
