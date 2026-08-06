import { Finding, Severity } from './types';

/**
 * Vulnérabilités applicatives.
 *
 * Contrairement aux règles SAST génériques (« eval est dangereux »), chacune
 * décrit ici un chemin d'attaque concret. Les motifs exigent la présence d'une
 * donnée contrôlée par l'appelant : signaler `fetch(url)` n'apprend rien,
 * signaler `fetch(req.body.url)` désigne une SSRF.
 */

interface WebSecRule {
  id: string;
  name: string;
  regex: RegExp;
  languages: RegExp;
  severity: Severity;
  description: string;
  fix: string;
  /** Motif disculpant, évalué sur une fenêtre de lignes autour du match. */
  exempt?: RegExp;
  /**
   * Règle valable uniquement côté serveur.
   * Une SSRF suppose que la requête part du serveur : le même `fetch` dans un
   * composant `"use client"` s'exécute dans le navigateur de l'utilisateur et
   * n'atteint rien qu'il ne puisse déjà atteindre.
   */
  serverOnly?: boolean;
  /** Motif systémique : un seul finding groupé plutôt qu'un par occurrence. */
  aggregate?: boolean;
}

/** Le fichier est-il un composant navigateur ? */
function isClientFile(text: string): boolean {
  return /^\s*['"]use client['"]/m.test(text.slice(0, 200));
}

const JS = /\.([jt]sx?|mjs|cjs)$/i;
const PY = /\.py$/i;

/** Marqueurs d'une donnée fournie par l'appelant. */
const INPUT = String.raw`(req|request)\.(body|query|params)[\w.\[\]'"]*|searchParams\.get\([^)]*\)|params\.\w+|body\.\w+`;

const RULES: WebSecRule[] = [
  {
    id: 'WEB-SSRF-001',
    serverOnly: true,
    name: 'Requête sortante vers une URL fournie par l\'utilisateur',
    regex: new RegExp(String.raw`\b(fetch|axios\.(get|post)|got|request|http\.get)\s*\(\s*[^)]*(${INPUT})`),
    languages: JS,
    severity: 'high',
    description:
      'Une URL contrôlée par l\'appelant est utilisée pour une requête sortante (SSRF). Depuis votre serveur, un attaquant atteint alors ce que vous seul pouvez joindre : services internes, bases non exposées, et surtout les métadonnées cloud (169.254.169.254) qui délivrent des identifiants IAM.',
    fix: 'Validez contre une liste blanche de domaines autorisés, refusez les adresses privées et de bouclage après résolution DNS, et interdisez les redirections.',
  },
  {
    id: 'WEB-RED-001',
    name: 'Redirection vers une destination fournie par l\'utilisateur',
    regex: new RegExp(String.raw`\b(redirect|res\.redirect|NextResponse\.redirect)\s*\(\s*[^)]*(${INPUT})`),
    languages: JS,
    severity: 'medium',
    description:
      'La destination de redirection vient de l\'appelant : un lien vers votre domaine peut renvoyer vers un site contrôlé par l\'attaquant. C\'est le socle des campagnes d\'hameçonnage crédibles, et cela permet de faire fuiter un jeton présent dans l\'URL.',
    fix: 'N\'acceptez que des chemins relatifs, ou validez la destination contre une liste blanche d\'URL internes.',
  },
  {
    id: 'WEB-NOSQL-001',
    serverOnly: true,
    name: 'Opérateur MongoDB contrôlé par l\'utilisateur',
    regex: new RegExp(String.raw`\$where\s*:|\.find\s*\(\s*\{[^}]*(${INPUT})`),
    languages: JS,
    severity: 'high',
    description:
      'Une valeur de requête MongoDB provient directement de l\'appelant. En envoyant `{"password": {"$ne": null}}` au lieu d\'une chaîne, on contourne une comparaison — et `$where` exécute du JavaScript côté serveur.',
    fix: 'Contraignez le type avant la requête (`String(req.body.email)`), refusez les objets là où vous attendez une chaîne, et n\'utilisez jamais `$where`.',
  },
  {
    id: 'WEB-MASS-001',
    serverOnly: true,
    name: 'Corps de requête transmis tel quel à la base',
    // Le corps peut être imbriqué (`create({ data: { ...req.body } })`) : on
    // autorise du contenu entre l'appel et le spread, sans franchir la parenthèse.
    regex: /\.(create|update|updateOne|updateMany|insertOne|insertMany|findOneAndUpdate|save)\s*\([^)]{0,120}\.\.\.\s*(req|request)\.body/,
    languages: JS,
    severity: 'high',
    description:
      'Le corps de la requête est diffusé tel quel vers la base (mass assignment). Un champ non prévu — `role: "admin"`, `isVerified: true`, `credits: 99999` — est écrit sans contrôle, car rien ne limite les clés acceptées.',
    fix: 'Extrayez explicitement les champs autorisés : `const { titre, contenu } = req.body;` puis n\'écrivez que ceux-là.',
  },
  {
    id: 'WEB-RAND-001',
    name: 'Aléa non cryptographique pour une valeur de sécurité',
    regex: /(token|secret|otp|code|nonce|salt|resetKey|sessionId|apiKey)\w*\s*[:=][^;\n]*Math\.random\s*\(/i,
    languages: JS,
    severity: 'high',
    description:
      '`Math.random()` est prévisible : son état interne se reconstitue à partir de quelques valeurs observées. Un jeton de réinitialisation ou de session ainsi produit peut être deviné.',
    fix: 'crypto.randomUUID(), ou crypto.randomBytes(32).toString("hex") pour un jeton.',
  },
  {
    id: 'WEB-TIME-001',
    serverOnly: true,
    name: 'Comparaison de secret non résistante au temps',
    // `password` est volontairement absent : comparer deux champs de formulaire
    // (`password !== confirmPassword`) ne présente aucun risque temporel.
    regex: /\b(token|secret|signature|hmac|apiKey|digest)\w*\s*(===?|!==?)\s*\w|\w\s*(===?|!==?)\s*\w*(token|secret|signature|hmac)\b/i,
    languages: JS,
    severity: 'medium',
    description:
      'Une comparaison `===` s\'arrête au premier caractère différent : le temps de réponse révèle combien de caractères sont corrects, ce qui permet de reconstituer la valeur caractère par caractère.',
    fix: 'crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b)) — après avoir vérifié que les longueurs correspondent.',
  },
  {
    id: 'WEB-COOKIE-001',
    serverOnly: true,
    name: 'Cookie de session sans httpOnly',
    regex: /(cookies?\.set|setCookie|res\.cookie)\s*\([^)]*\)/,
    exempt: /httpOnly\s*:\s*true/i,
    languages: JS,
    severity: 'medium',
    description:
      'Un cookie sans `httpOnly` est lisible en JavaScript : la moindre XSS suffit alors à exfiltrer la session.',
    fix: '{ httpOnly: true, secure: true, sameSite: "lax" } — httpOnly contre le vol, secure contre l\'interception, sameSite contre le CSRF.',
  },
  {
    id: 'WEB-JWT-001',
    serverOnly: true,
    name: 'Vérification JWT permissive',
    regex: /algorithms?\s*:\s*\[?\s*['"]none['"]|jwt\.decode\s*\(|verify\s*\([^)]*\{\s*\}\s*\)/,
    languages: JS,
    severity: 'critical',
    description:
      '`jwt.decode()` lit le jeton SANS vérifier la signature, et accepter l\'algorithme `none` revient à faire confiance à un jeton non signé. Dans les deux cas, n\'importe qui peut forger une identité.',
    fix: 'jwt.verify(token, cle, { algorithms: ["HS256"] }) — en fixant explicitement l\'algorithme attendu.',
  },
  {
    id: 'WEB-CORS-001',
    serverOnly: true,
    name: 'Origine CORS reflétée',
    regex: /Access-Control-Allow-Origin['"]?\s*[,:]\s*[^'"\n]*(req|request)\.headers|origin\s*:\s*true/i,
    languages: JS,
    severity: 'high',
    description:
      'L\'origine de la requête est renvoyée telle quelle en `Access-Control-Allow-Origin`. Associé à `credentials: true`, cela autorise n\'importe quel site à appeler votre API avec les cookies de vos utilisateurs.',
    fix: 'Comparez l\'origine à une liste blanche explicite et ne renvoyez l\'en-tête que si elle y figure.',
  },
  {
    id: 'WEB-LEAK-001',
    aggregate: true,
    serverOnly: true,
    name: 'Détail d\'erreur renvoyé au client',
    regex: /(res\.(json|send)|Response\.json|NextResponse\.json)\s*\(\s*\{?[^)]*\b(err|error|e)\.(stack|message)\b/,
    languages: JS,
    severity: 'medium',
    description:
      'Le message ou la pile d\'appel est renvoyé au client : chemins du serveur, versions des bibliothèques, parfois fragments de requête SQL. C\'est la phase de reconnaissance offerte à l\'attaquant.',
    fix: 'Journalisez le détail côté serveur et renvoyez un message générique accompagné d\'un identifiant de corrélation.',
  },
  {
    id: 'WEB-LOG-001',
    name: 'Secret écrit dans les journaux',
    regex: /console\.(log|info|debug|warn)\s*\([^)]*\b(password|passwd|token|secret|apiKey|authorization|creditCard)\b/i,
    languages: JS,
    severity: 'medium',
    description:
      'Un secret passe dans les journaux. Ceux-ci sont souvent conservés longtemps, agrégés chez un tiers et accessibles à toute l\'équipe — un secret qui y entre doit être considéré comme divulgué.',
    fix: 'Masquez la valeur avant journalisation, ou retirez complètement l\'appel.',
  },
  {
    id: 'WEB-UPLOAD-001',
    serverOnly: true,
    name: 'Nom de fichier téléversé utilisé sans nettoyage',
    regex: /(writeFile|createWriteStream|rename|copyFile|join|resolve)\s*\([^)]*\b(originalname|filename|file\.name)\b/i,
    languages: JS,
    severity: 'high',
    description:
      'Le nom de fichier fourni par le client sert à construire un chemin d\'écriture. Un nom contenant `../` permet d\'écrire hors du dossier prévu — jusqu\'à remplacer un fichier de configuration ou déposer un script exécutable.',
    fix: 'Générez le nom vous-même (crypto.randomUUID()), conservez le nom d\'origine en métadonnée, et validez le type réel du contenu — pas l\'extension.',
  },

  // --- Python ---
  {
    id: 'WEB-PY-001',
    serverOnly: true,
    name: 'Requête sortante vers une URL fournie par l\'utilisateur',
    // httpx et aiohttp sont les clients par défaut d'une API asynchrone
    // (FastAPI) : les ignorer laissait passer la même SSRF que `requests`.
    regex:
      /\b(requests|httpx|client|session)\.(get|post|put|patch|delete|stream|request)\s*\(\s*[^)]*(request\.(args|form|json|GET|POST)|params\[)|urlopen\s*\(\s*[^)]*request\.(args|form|json|GET|POST)/,
    languages: PY,
    severity: 'high',
    description:
      'URL contrôlée par l\'appelant dans une requête sortante (SSRF) : accès aux services internes et aux métadonnées cloud depuis votre serveur.',
    fix: 'Validez contre une liste blanche de domaines et refusez les adresses privées après résolution DNS.',
  },
  {
    id: 'WEB-PY-002',
    serverOnly: true,
    name: 'Requête SQL construite par formatage',
    regex: /(execute|executemany)\s*\(\s*[^)]*(%\s*\(|\.format\s*\(|f['"])/,
    languages: PY,
    severity: 'high',
    description:
      'La requête SQL est assemblée par formatage de chaîne : la donnée fournie est interprétée comme du code SQL.',
    fix: 'Passez les valeurs en paramètres : cursor.execute("SELECT … WHERE id = %s", (id,)).',
  },

  // --- FastAPI / Starlette ---
  {
    id: 'WEB-PY-003',
    serverOnly: true,
    name: 'CORS ouvert à toutes les origines',
    regex:
      /allow_origins\s*=\s*\[?\s*["']\*["']|allow_origin_regex\s*=\s*["'](\.\*|\^?\.\*\$?)["']/,
    languages: PY,
    severity: 'high',
    description:
      'Le middleware CORS accepte n\'importe quelle origine. Combiné à `allow_credentials=True` — ce que FastAPI accepte sans broncher alors que la spécification l\'interdit avec `*` — n\'importe quel site peut appeler votre API avec les cookies de vos utilisateurs et lire les réponses.',
    fix: 'Énumérez les origines : allow_origins=["https://app.exemple.fr"]. Si vous avez besoin de plusieurs domaines dynamiques, comparez `request.headers["origin"]` à une liste blanche avant de répondre.',
  },
  {
    id: 'WEB-PY-004',
    serverOnly: true,
    name: 'Jeton JWT décodé sans vérification de signature',
    regex:
      /["']verify_signature["']\s*:\s*False|jwt\.decode\s*\([^)]*verify\s*=\s*False|get_unverified_claims\s*\(|jwt\.get_unverified_header\s*\([^)]*\)\s*\[/,
    languages: PY,
    severity: 'critical',
    description:
      'Le contenu du jeton est lu sans que la signature soit vérifiée : n\'importe qui peut en forger un et se déclarer administrateur. `verify_signature: False` n\'a de sens que dans un test, jamais sur un chemin de requête.',
    fix: 'jwt.decode(token, cle, algorithms=["HS256"]) — en fixant explicitement l\'algorithme attendu, et en interceptant JWTError pour renvoyer un 401.',
  },
  {
    id: 'WEB-PY-005',
    serverOnly: true,
    name: 'SQLAlchemy : requête text() assemblée par formatage',
    regex: /\btext\s*\(\s*(f["']|["'][^"']*["']\s*[+%]|["'][^"']*["']\s*\.\s*format\s*\()/,
    languages: PY,
    severity: 'high',
    description:
      '`text()` livre la chaîne au moteur telle quelle : l\'assembler par f-string ou concaténation replace exactement l\'injection SQL que l\'ORM évitait. Un `id` valant `1 OR 1=1` change le sens de la requête.',
    fix: 'Utilisez des paramètres liés : session.execute(text("SELECT … WHERE id = :id"), {"id": id}) — ou restez sur les constructions ORM (select(Article).where(Article.id == id)).',
  },
  {
    id: 'WEB-PY-006',
    serverOnly: true,
    name: 'Chemin de fichier construit avec une donnée de requête',
    regex:
      /\b(open|FileResponse|send_file|os\.remove|shutil\.(copy|move)|Path)\s*\(\s*f["'][^"']*\{/,
    languages: PY,
    severity: 'high',
    description:
      'Un chemin de fichier est interpolé dans une f-string. Sur une route de téléchargement, un nom contenant `../../etc/passwd` sort du dossier prévu — et sur une écriture ou une suppression, il atteint des fichiers du serveur.',
    fix: 'Résolvez le chemin puis vérifiez qu\'il reste sous la racine autorisée : `chemin = (RACINE / nom).resolve()` suivi de `chemin.is_relative_to(RACINE.resolve())`. Mieux : ne jamais accepter de nom de fichier, mais un identifiant que vous traduisez vous-même.',
  },
  {
    id: 'WEB-PY-007',
    serverOnly: true,
    name: 'HTML assemblé par interpolation dans la réponse',
    regex: /\b(HTMLResponse|Markup|render_template_string)\s*\(\s*f["']|HTMLResponse\s*\(\s*[^)]*\+/,
    languages: PY,
    severity: 'high',
    description:
      'Le HTML renvoyé est construit par interpolation : une valeur venue de l\'appelant qui contient `<script>` s\'exécute dans le navigateur de la victime (XSS). Contrairement aux templates Jinja2, aucune échappement n\'a lieu ici.',
    fix: 'Passez par un template avec échappement automatique (Jinja2Templates de FastAPI) et transmettez les valeurs en contexte, jamais dans la chaîne du template.',
  },
  {
    id: 'WEB-PY-008',
    name: 'Échappement automatique des templates désactivé',
    regex: /autoescape\s*=\s*False/,
    languages: PY,
    severity: 'high',
    description:
      'Sans échappement automatique, chaque variable insérée dans un template est du HTML brut : toute valeur d\'origine utilisateur devient une XSS potentielle, et il suffit d\'un oubli de `|e` pour ouvrir la faille.',
    fix: 'autoescape=True (ou select_autoescape()) et utilisez `|safe` ponctuellement, uniquement sur du contenu que vous avez vous-même produit ou nettoyé.',
  },
];

/** Extensions concernées par les règles applicatives. */
export const WEBSEC_FILE_TYPES = /\.([jt]sx?|mjs|cjs|py)$/i;

const COMMENT = /^\s*(\/\/|#|\*)/;
const EXEMPT_WINDOW = 3;

/** Applique les règles applicatives au contenu d'un fichier déjà lu. */
export function scanWebSecInText(fsPath: string, relPath: string, text: string): Finding[] {
  const clientSide = isClientFile(text);
  const applicable = RULES.filter(
    (r) => r.languages.test(fsPath) && !(clientSide && r.serverOnly)
  );
  if (applicable.length === 0) return [];

  const findings: Finding[] = [];
  const lines = text.split(/\r?\n/);

  lines.forEach((line, i) => {
    if (COMMENT.test(line)) return;
    for (const rule of applicable) {
      if (!rule.regex.test(line)) continue;

      if (rule.exempt) {
        const window = lines
          .slice(Math.max(0, i - EXEMPT_WINDOW), i + EXEMPT_WINDOW + 1)
          .join('\n');
        if (rule.exempt.test(window)) continue;
      }

      findings.push({
        kind: 'websec',
        severity: rule.severity,
        id: rule.id,
        title: `${rule.name} (${rule.id})`,
        description: `${rule.description}\n\n**Correctif**\n${rule.fix}`,
        file: relPath,
        line: i + 1,
      });
    }
  });

  return findings;
}

/**
 * Regroupe les motifs systémiques (une même erreur répétée partout) en un
 * finding unique : c'est une correction à passer sur l'ensemble du code, pas
 * vingt problèmes distincts.
 */
export function aggregateWebSec(findings: Finding[]): Finding[] {
  const aggregatable = new Set(RULES.filter((r) => r.aggregate).map((r) => r.id));
  const byRule = new Map<string, Finding[]>();
  const out: Finding[] = [];

  for (const f of findings) {
    if (!aggregatable.has(f.id ?? '')) {
      out.push(f);
      continue;
    }
    const list = byRule.get(f.id ?? '');
    if (list) list.push(f);
    else byRule.set(f.id ?? '', [f]);
  }

  for (const [, group] of byRule) {
    if (group.length === 1) {
      out.push(group[0]);
      continue;
    }
    const files = [...new Set(group.map((f) => f.file ?? ''))];
    const shown = files.slice(0, 8).map((f) => `• ${f}`).join('\n');
    const more = files.length > 8 ? `\n• … et ${files.length - 8} autre(s)` : '';

    out.push({
      ...group[0],
      title: `${group[0].title} — ${group.length} occurrence(s) dans ${files.length} fichier(s)`,
      description: `${group[0].description}\n\n**Où (${files.length} fichiers)**\n${shown}${more}`,
    });
  }

  return out;
}
