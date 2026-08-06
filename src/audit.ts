import { Finding, Severity } from './types';

/**
 * Audit de posture : ce qu'un auditeur humain regarde, et qu'aucun scanner à
 * base de motifs ne voit.
 *
 * Une regex trouve un mauvais motif PRÉSENT. Elle ne trouve jamais une
 * protection ABSENTE — or c'est là que sont les vraies failles : une route sans
 * contrôle d'accès, une API sans limitation de débit, un formulaire sans
 * validation. Ce module raisonne donc sur le projet entier plutôt que ligne à
 * ligne, et croise les signaux : « cette route lit une entrée utilisateur ET
 * interroge la base ET ne vérifie aucune session ».
 */

// ---------------------------------------------------------------------------
// Reconnaissance des routes
// ---------------------------------------------------------------------------

/** Next.js App Router : app/api/**\/route.ts */
const NEXT_APP_ROUTE = /[\\/]app[\\/].*[\\/]route\.[jt]sx?$/i;
/** Next.js Pages Router : pages/api/** */
const NEXT_PAGES_ROUTE = /[\\/]pages[\\/]api[\\/].*\.[jt]sx?$/i;
/** NestJS */
const NEST_CONTROLLER = /\.controller\.[jt]s$/i;
/** Express / Fastify / Hono : un routeur déclaré dans le fichier. */
const EXPRESS_ROUTE = /\b(router|app)\.(get|post|put|patch|delete|all)\s*\(/;

/** Le fichier expose-t-il une route HTTP ? */
function isRouteFile(fsPath: string, text: string): boolean {
  return (
    NEXT_APP_ROUTE.test(fsPath) ||
    NEXT_PAGES_ROUTE.test(fsPath) ||
    NEST_CONTROLLER.test(fsPath) ||
    EXPRESS_ROUTE.test(text)
  );
}

/** Vérification d'identité, tous frameworks confondus. */
const AUTH_CHECK =
  /getServerSession|getServerAuthSession|\bauth\s*\(\s*\)|getToken\s*\(|requireAuth|verifyToken|verifyJwt|@UseGuards|isAuthenticated|currentUser|getCurrentUser|withAuth|authMiddleware|getAuth\s*\(|clerkClient|session\s*[?.]|ensureLoggedIn|checkPermission|authorize\s*\(/i;

/** Accès à une base de données. */
const DB_ACCESS =
  /\bprisma\s*\.|\bdb\s*\.|mongoose|\bknex\s*\(|drizzle|supabase|createClient|\.findMany\s*\(|\.findUnique\s*\(|\.aggregate\s*\(|sql`|\.query\s*\(/i;

/**
 * Lecture d'une donnée contrôlée par l'appelant.
 * Motifs volontairement précis : un `params\s*[.:]` large matchait tout objet
 * contenant une clé `params`, et signalait des routes qui ne lisent rien.
 */
const USER_INPUT =
  /\breq(uest)?\.(body|query|params)\b|\brequest\.(json|formData|text)\s*\(|\bsearchParams\.(get|getAll|has)\s*\(|\bawait\s+req\.(json|formData|text)\s*\(|\bparams\.\w+/;

/**
 * Validation d'entrée — bibliothèque de schéma OU garde manuelle explicite.
 * Vérifier soi-même avec `isValidObjectId` est une validation parfaitement
 * valable : ne pas la reconnaître produisait de faux reproches.
 */
const VALIDATION =
  /\bz\s*\.\s*(object|string|number)|zodResolver|\bjoi\.|\byup\.|class-validator|ValidationPipe|valibot|\bajv\b|\.safeParse\s*\(|\.parse\s*\(|isValidObjectId|isUUID|isEmail|\bvalidator\./i;

/** Limitation de débit. */
const RATE_LIMIT =
  /rate-?limit|ratelimit|Throttler|@upstash\/ratelimit|express-rate-limit|slowDown|bottleneck/i;

/** En-têtes de sécurité. */
const SECURITY_HEADERS =
  /Content-Security-Policy|Strict-Transport-Security|X-Frame-Options|helmet\s*\(|X-Content-Type-Options|Referrer-Policy/i;

/** Protection CSRF. */
const CSRF = /csrf|csurf|sameSite\s*:\s*['"](strict|lax)['"]/i;

/** Route sensible : c'est là que la limitation de débit compte vraiment. */
const AUTH_ROUTE = /[\\/](login|signin|sign-in|register|signup|sign-up|auth|password|reset|forgot|token|otp|verify)[\\/\\.]/i;

// ---------------------------------------------------------------------------

export interface RouteInfo {
  file: string;
  hasAuth: boolean;
  touchesDb: boolean;
  readsInput: boolean;
  validates: boolean;
  isAuthRoute: boolean;
}

export interface AuditSignals {
  routes: RouteInfo[];
  hasRateLimit: boolean;
  hasSecurityHeaders: boolean;
  hasCsrf: boolean;
  hasValidationLib: boolean;
  /** Fichiers d'environnement trouvés (hors .example). */
  envFiles: string[];
  /** Clés privées, certificats, jetons de registre trouvés dans l'arborescence. */
  sensitiveFiles: string[];
  /** Contenu cumulé des .gitignore rencontrés. */
  gitignore: string;
}

/**
 * Fichiers dont la présence dans un dépôt est un problème en soi.
 * Une clé privée versionnée est compromise, quelle que soit la suite.
 */
const SENSITIVE_FILE =
  /(^|[\\/])(id_rsa|id_dsa|id_ecdsa|id_ed25519|\.npmrc|\.pypirc|\.netrc|\.htpasswd)$|\.(pem|key|p12|pfx|jks|keystore|ppk)$|(^|[\\/])(service-account|serviceaccount|credentials|gcp-key|firebase-adminsdk)[\w.-]*\.json$/i;

export function emptySignals(): AuditSignals {
  return {
    routes: [],
    hasRateLimit: false,
    hasSecurityHeaders: false,
    hasCsrf: false,
    hasValidationLib: false,
    envFiles: [],
    sensitiveFiles: [],
    gitignore: '',
  };
}

/** Fichiers utiles à l'audit de posture, au-delà du code applicatif. */
export const AUDIT_FILE_TYPES = new RegExp(
  [
    String.raw`(^|[\\/])(\.gitignore|next\.config\.\w+|middleware\.[jt]s|nuxt\.config\.\w+|vite\.config\.\w+|\.env[\w.]*)$`,
    String.raw`\.([jt]sx?|mjs|cjs)$`,
    SENSITIVE_FILE.source,
  ].join('|'),
  'i'
);

/** Relève, fichier par fichier, les signaux nécessaires à l'audit global. */
export function collectAuditSignals(
  fsPath: string,
  relPath: string,
  text: string,
  signals: AuditSignals
): void {
  const base = relPath.split(/[\\/]/).pop() ?? '';

  if (base === '.gitignore') {
    signals.gitignore += `\n${text}`;
    return;
  }

  if (/^\.env(\.|$)/.test(base) && !/\.(example|sample|template)$/.test(base)) {
    signals.envFiles.push(relPath);
    return;
  }

  if (SENSITIVE_FILE.test(relPath)) {
    signals.sensitiveFiles.push(relPath);
    return;
  }

  if (RATE_LIMIT.test(text)) signals.hasRateLimit = true;
  if (SECURITY_HEADERS.test(text)) signals.hasSecurityHeaders = true;
  if (CSRF.test(text)) signals.hasCsrf = true;
  if (VALIDATION.test(text)) signals.hasValidationLib = true;

  if (isRouteFile(fsPath, text)) {
    signals.routes.push({
      file: relPath,
      hasAuth: AUTH_CHECK.test(text),
      touchesDb: DB_ACCESS.test(text),
      readsInput: USER_INPUT.test(text),
      validates: VALIDATION.test(text),
      isAuthRoute: AUTH_ROUTE.test(relPath),
    });
  }
}

// ---------------------------------------------------------------------------
// Production des constats
// ---------------------------------------------------------------------------

function list(files: string[], max = 10): string {
  const shown = files.slice(0, max).map((f) => `• ${f}`).join('\n');
  return files.length > max ? `${shown}\n• … et ${files.length - max} autre(s)` : shown;
}

function finding(
  id: string,
  severity: Severity,
  title: string,
  description: string,
  file?: string
): Finding {
  return { kind: 'audit', severity, id, title, description, file };
}

/** `.env` est-il couvert par un `.gitignore` ? */
function envIsIgnored(gitignore: string): boolean {
  return /^\s*\*?\.env/m.test(gitignore) || /^\s*\.env\*/m.test(gitignore);
}

/**
 * Constats d'audit à l'échelle du projet.
 * Chaque constat répond à une question qu'un auditeur pose réellement.
 */
export function auditFindings(signals: AuditSignals): Finding[] {
  const out: Finding[] = [];
  const { routes } = signals;

  // --- Secrets versionnés : le risque le plus direct ---
  if (signals.envFiles.length > 0 && !envIsIgnored(signals.gitignore)) {
    out.push(
      finding(
        'NDK-AUD-001',
        'critical',
        `${signals.envFiles.length} fichier(s) .env non couvert(s) par .gitignore`,
        'Un fichier d\'environnement non ignoré finit tôt ou tard dans un commit — et un secret publié doit être considéré comme compromis, même après suppression : il reste dans l\'historique Git.\n\n' +
          `**Fichiers**\n${list(signals.envFiles)}\n\n` +
          '**À faire**\n1. Ajoutez `.env*` à votre `.gitignore` (en gardant `!.env.example`).\n' +
          '2. Vérifiez l\'historique : `git log --all --full-history -- .env`.\n' +
          '3. Si le fichier a été commité, révoquez TOUS les secrets qu\'il contient avant de nettoyer l\'historique.',
        signals.envFiles[0]
      )
    );
  }

  // --- Clés et certificats dans l'arborescence ---
  if (signals.sensitiveFiles.length > 0) {
    out.push(
      finding(
        'NDK-AUD-008',
        'critical',
        `${signals.sensitiveFiles.length} fichier(s) de clé ou d'identifiants dans le projet`,
        'Clés privées, certificats ou jetons de registre présents dans l\'arborescence. ' +
          'S\'ils sont versionnés, ils sont à considérer comme compromis : un dépôt se clone, et l\'historique conserve tout.\n\n' +
          `**Fichiers**\n${list(signals.sensitiveFiles)}\n\n` +
          '**À faire**\n1. Vérifiez s\'ils sont suivis par Git : `git ls-files | grep -E "\\.(pem|key|p12)$"`.\n' +
          '2. Si oui : révoquez et régénérez AVANT de nettoyer l\'historique — la suppression seule ne protège de rien.\n' +
          '3. Ajoutez ces motifs au `.gitignore` et sortez les clés du dépôt (gestionnaire de secrets, montage au déploiement).',
        signals.sensitiveFiles[0]
      )
    );
  }

  if (routes.length === 0) return out;

  // --- Carte de la surface d'attaque ---
  const withAuth = routes.filter((r) => r.hasAuth).length;
  out.push(
    finding(
      'NDK-AUD-002',
      'info',
      `Surface d'attaque : ${routes.length} route(s) HTTP exposée(s)`,
      `Nodock a recensé ${routes.length} route(s), dont ${withAuth} comportant une vérification d'identité ` +
        `et ${routes.filter((r) => r.touchesDb).length} accédant à la base de données.\n\n` +
        'Cette carte n\'est pas un problème en soi : c\'est le périmètre à couvrir. ' +
        'Chaque route est une porte d\'entrée que quelqu\'un peut appeler directement, sans passer par votre interface.'
    )
  );

  // --- Routes sans contrôle d'accès ---
  const unauth = routes.filter((r) => !r.hasAuth && r.touchesDb);
  if (unauth.length > 0) {
    out.push(
      finding(
        'NDK-AUD-003',
        'high',
        `${unauth.length} route(s) accèdent à la base sans vérification d'identité`,
        'Ces routes interrogent ou modifient la base sans qu\'aucune vérification de session ne soit détectée. ' +
          'Certaines sont peut-être publiques à dessein (catalogue, santé, webhook signé) — mais chacune mérite d\'être confirmée.\n\n' +
          `**Routes**\n${list(unauth.map((r) => r.file))}\n\n` +
          '**À faire**\n1. Pour chacune : cette donnée doit-elle être lisible/modifiable sans être connecté ?\n' +
          '2. Si non, ajoutez la vérification de session en TOUT DÉBUT de handler.\n' +
          '3. Vérifiez aussi l\'autorisation, pas seulement l\'authentification : être connecté ne donne pas le droit de lire les données d\'autrui.\n' +
          '4. Pour les webhooks, validez la signature de l\'émetteur.',
        unauth[0].file
      )
    );
  }

  // --- Entrée utilisateur non validée jusqu'à la base ---
  const unvalidated = routes.filter((r) => r.readsInput && r.touchesDb && !r.validates);
  if (unvalidated.length > 0) {
    out.push(
      finding(
        'NDK-AUD-004',
        'high',
        `${unvalidated.length} route(s) mènent une entrée utilisateur jusqu'à la base sans validation`,
        'Ces routes lisent une donnée fournie par l\'appelant et l\'utilisent dans un accès base, sans schéma de validation détecté. ' +
          'C\'est le chemin classique vers l\'injection, la pollution de champs (mass assignment) et les accès indirects à des objets d\'autrui.\n\n' +
          `**Routes**\n${list(unvalidated.map((r) => r.file))}\n\n` +
          '**À faire**\n1. Validez la forme des entrées avec un schéma (zod, joi, class-validator) dès l\'entrée du handler.\n' +
          '2. N\'acceptez que les champs attendus — ne passez jamais le corps de requête entier à un `create`/`update`.\n' +
          '3. Vérifiez que l\'identifiant demandé appartient bien à l\'utilisateur courant.',
        unvalidated[0].file
      )
    );
  }

  // --- Limitation de débit sur les routes sensibles ---
  const authRoutes = routes.filter((r) => r.isAuthRoute);
  if (authRoutes.length > 0 && !signals.hasRateLimit) {
    out.push(
      finding(
        'NDK-AUD-005',
        'high',
        `Aucune limitation de débit sur ${authRoutes.length} route(s) d'authentification`,
        'Sans limitation, ces routes se prêtent au bourrage d\'identifiants, à l\'énumération de comptes et à l\'envoi massif d\'emails de réinitialisation.\n\n' +
          `**Routes concernées**\n${list(authRoutes.map((r) => r.file))}\n\n` +
          '**À faire**\n1. Limitez par IP ET par identifiant visé (sinon l\'attaque répartie passe).\n' +
          '2. Renvoyez le même message et le même délai que l\'identifiant existe ou non.\n' +
          '3. Ajoutez un délai progressif ou un CAPTCHA après plusieurs échecs.',
        authRoutes[0].file
      )
    );
  }

  // --- En-têtes de sécurité ---
  if (!signals.hasSecurityHeaders) {
    out.push(
      finding(
        'NDK-AUD-006',
        'medium',
        'Aucun en-tête de sécurité HTTP configuré',
        'Aucune trace de Content-Security-Policy, HSTS, X-Frame-Options ni de helmet. ' +
          'Ces en-têtes sont la dernière ligne de défense : ils limitent l\'impact d\'une XSS et empêchent le détournement de clic.\n\n' +
          '**À faire**\n' +
          '1. `Content-Security-Policy` — la plus efficace contre les XSS, à déployer d\'abord en `Report-Only`.\n' +
          '2. `Strict-Transport-Security: max-age=31536000; includeSubDomains`.\n' +
          '3. `X-Frame-Options: DENY` (ou `frame-ancestors` dans la CSP).\n' +
          '4. `X-Content-Type-Options: nosniff` et `Referrer-Policy: strict-origin-when-cross-origin`.\n\n' +
          'En Next.js, cela se déclare dans `headers()` de `next.config`. Avec Express, via `helmet()`.'
      )
    );
  }

  // --- Validation d'entrée à l'échelle du projet ---
  if (!signals.hasValidationLib && routes.some((r) => r.readsInput)) {
    out.push(
      finding(
        'NDK-AUD-007',
        'medium',
        'Aucune bibliothèque de validation d\'entrée détectée',
        'Des routes lisent des données fournies par l\'appelant, mais aucun schéma de validation n\'a été trouvé dans le projet. ' +
          'La validation côté navigateur ne compte pas : elle est contournée par un simple appel direct à l\'API.\n\n' +
          '**À faire**\nAdoptez un schéma par route (zod s\'intègre bien à TypeScript et infère les types) ' +
          'et refusez toute requête non conforme avant d\'exécuter la moindre logique.'
      )
    );
  }

  return out;
}
