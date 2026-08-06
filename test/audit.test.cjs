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

test('recense les routes Python, PHP et Java', () => {
  const s = signalsFrom({
    'app/urls.py': 'from django.urls import path\nurlpatterns = [path("users/", users)]',
    'api/views.py': '@app.route("/items")\ndef items():\n    return db.session.query(Item).all()',
    'routes/web.php': "Route::post('/login', [AuthController::class, 'login']);",
    'src/UserController.java': '@GetMapping("/users")\npublic List<User> users() { return repo.findAll(); }',
    'src/utils.py': 'def helper():\n    return 42',
  });
  assert.equal(s.routes.length, 4, 'l\'utilitaire Python n\'est pas une route');
  const login = s.routes.find((r) => r.file === 'routes/web.php');
  assert.ok(login.isAuthRoute, 'Route::post(\'/login\') est une route d\'authentification');
});

test('routes d\'auth Python sans rate-limit → NDK-AUD-005', () => {
  const s = signalsFrom({
    'api/auth.py': '@app.post("/login")\ndef login():\n    return {}',
  });
  const f = byId(auditFindings(s), 'NDK-AUD-005');
  assert.ok(f, 'une route /login sans limitation de débit doit être signalée');
});

test('flask-limiter coupe l\'alerte rate-limit', () => {
  const s = signalsFrom({
    'api/auth.py': '@app.post("/login")\ndef login():\n    return {}',
    'api/limit.py': 'from flask_limiter import Limiter\nlimiter = Limiter(app)',
  });
  assert.equal(byId(auditFindings(s), 'NDK-AUD-005'), undefined);
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

// ---------------------------------------------------------------------------
// FastAPI : l'authentification passe par l'injection de dépendance et l'entrée
// utilisateur par la signature du handler — deux conventions que les motifs
// pensés pour Express/Next ne voient pas.
// ---------------------------------------------------------------------------

const FASTAPI_PROTECTED = `
from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

router = APIRouter()

@router.get("/factures")
async def lister(user = Depends(get_current_user), session: AsyncSession = Depends(get_session)):
    return await session.scalars(select(Facture).where(Facture.user_id == user.id))
`;

const FASTAPI_OPEN = `
from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

router = APIRouter()

@router.get("/factures")
async def lister(session: AsyncSession = Depends(get_session)):
    return await session.scalars(select(Facture))
`;

test('FastAPI : une route est reconnue comme route', () => {
  const s = signalsFrom({ 'app/routers/factures.py': FASTAPI_OPEN });
  assert.equal(s.routes.length, 1);
  assert.ok(s.routes[0].touchesDb, 'session.scalars() est un accès base');
});

test('FastAPI : Depends(get_current_user) compte comme vérification d\'identité', () => {
  const s = signalsFrom({ 'app/routers/factures.py': FASTAPI_PROTECTED });
  assert.ok(s.routes[0].hasAuth, 'faux positif : la route est protégée par injection');
  assert.equal(byId(auditFindings(s), 'NDK-AUD-003'), undefined);
});

test('FastAPI : Depends(get_session) seul ne vaut pas une authentification', () => {
  // Injecter une session de base n'est pas vérifier une identité : confondre
  // les deux masquerait précisément les routes à corriger.
  const s = signalsFrom({ 'app/routers/factures.py': FASTAPI_OPEN });
  assert.equal(s.routes[0].hasAuth, false);
  assert.equal(byId(auditFindings(s), 'NDK-AUD-003').severity, 'high');
});

test('FastAPI : une garde de routeur rétrograde le constat sans le masquer', () => {
  const s = signalsFrom({
    'app/routers/factures.py': FASTAPI_OPEN,
    'app/main.py':
      'app.include_router(factures.router, prefix="/api", dependencies=[Depends(get_current_user)])',
  });
  const f = byId(auditFindings(s), 'NDK-AUD-003');
  assert.equal(f.severity, 'medium', 'la garde globale peut couvrir ces routes');
  assert.ok(f.description.includes('dependencies'), 'le doute doit être expliqué');
});

test('FastAPI : l\'entrée utilisateur se lit dans la signature du handler', () => {
  const model = `
from pydantic import BaseModel

class ArticleIn(BaseModel):
    titre: str

@router.post("/articles")
async def creer(article: ArticleIn, session = Depends(get_session)):
    session.add(Article(**article.model_dump()))
`;
  const s = signalsFrom({ 'app/routers/articles.py': model });
  assert.ok(s.routes[0].readsInput, 'un paramètre typé Pydantic reçoit le corps de requête');

  const query = `
@router.get("/recherche")
async def chercher(q: str = Query(...), session = Depends(get_session)):
    return await session.execute(text("SELECT 1"))
`;
  assert.ok(signalsFrom({ 'app/routers/r.py': query }).routes[0].readsInput);

  const pathParam = `
@router.get("/articles/{article_id}")
async def lire(article_id: int, session = Depends(get_session)):
    return await session.scalars(select(Article))
`;
  assert.ok(
    signalsFrom({ 'app/routers/p.py': pathParam }).routes[0].readsInput,
    'un paramètre de chemin est fourni par l\'appelant'
  );
});

test('FastAPI : un fichier Python sans route ne lit rien', () => {
  const helper = `
from pydantic import BaseModel

class Config(BaseModel):
    debug_level: str
`;
  assert.equal(signalsFrom({ 'app/config.py': helper }).routes.length, 0);
});

test('FastAPI : slowapi satisfait la limitation de débit', () => {
  const s = signalsFrom({
    'app/routers/auth.py': `
from slowapi import Limiter

@router.post("/login")
async def login(form: LoginIn, session = Depends(get_session)):
    return await session.scalars(select(User))
`,
  });
  assert.equal(byId(auditFindings(s), 'NDK-AUD-005'), undefined);
});

test('FastAPI : une route de connexion sans limitation reste signalée', () => {
  const s = signalsFrom({
    'app/routers/auth.py': `
@router.post("/login")
async def login(form: LoginIn, session = Depends(get_session)):
    return await session.scalars(select(User))
`,
  });
  const f = byId(auditFindings(s), 'NDK-AUD-005');
  assert.ok(f, 'le chemin /login est reconnu dans le décorateur');
  assert.equal(f.severity, 'high');
});

test('FastAPI : un middleware d\'en-têtes satisfait NDK-AUD-006', () => {
  const s = signalsFrom({
    'app/main.py': `
@app.middleware("http")
async def headers(request, call_next):
    response = await call_next(request)
    response.headers["Strict-Transport-Security"] = "max-age=31536000"
    return response
`,
    'app/routers/x.py': FASTAPI_PROTECTED,
  });
  assert.equal(byId(auditFindings(s), 'NDK-AUD-006'), undefined);
});
