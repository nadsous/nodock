import { Finding, Triage, TriageProbe } from './types';

/**
 * Triage : est-ce que ce finding concerne réellement ce projet ?
 *
 * Un scanner qui se contente de comparer des numéros de version signale des
 * failles qu'aucun chemin de code n'atteint. Ce module cherche des preuves
 * dans le code avant d'affirmer qu'un problème est exploitable. Il ne conclut
 * JAMAIS à l'absence de vulnérabilité : au mieux « aucun chemin détecté ».
 */

// ---------------------------------------------------------------------------
// Extraction des symboles vulnérables depuis le texte de l'avis
// ---------------------------------------------------------------------------

/** Termes de protocole ou de config : présents dans les avis, mais pas des symboles de code. */
const NOISE = new Set([
  'client_secret', 'client_id', 'refresh_token', 'access_token', 'grant_type',
  'authorization', 'true', 'false', 'null', 'undefined', 'string', 'number',
  'get', 'post', 'put', 'delete', 'http', 'https', 'json', 'url', 'uri',
  'update', 'create', 'remove', 'list', 'token', 'user', 'users', 'session',
  'admin', 'config', 'options', 'data', 'value', 'name', 'type', 'error',
  'request', 'response', 'server', 'client', 'api', 'auth', 'login', 'logout',
  'password', 'email', 'role', 'key', 'id', 'path', 'file', 'query', 'body',
]);

/**
 * Un symbole est-il assez distinctif pour trancher à lui seul ?
 *
 * `oidcProvider` ou `deviceAuthorization` n'apparaissent que si l'API est
 * utilisée. `update` ou `token` apparaissent dans n'importe quel projet : les
 * trouver ne prouve rien, et conclure « exploitable » sur cette base est un
 * faux positif.
 */
export function isDistinctiveSymbol(symbol: string): boolean {
  // camelCase / PascalCase : une majuscule après le premier caractère.
  if (/[a-z][A-Z]/.test(symbol)) return true;
  // Identifiants composés : oidc-provider, two_factor.
  if (/[-_.]/.test(symbol)) return true;
  // Un mot simple en minuscules reste du vocabulaire courant, quelle que soit sa
  // longueur : `organization` ou `authorization` n'indiquent rien à eux seuls.
  return false;
}

/** Derniers segments qui désignent un dossier, pas un module précis. */
const CONTAINER_SEGMENT = new Set([
  'plugins', 'plugin', 'dist', 'lib', 'src', 'index', 'client', 'server',
  'react', 'vue', 'svelte', 'node', 'types', 'utils', 'core', 'api',
]);

/** `nomDeFonction()` — signal fort : c'est une API que le code appelle ou non. */
const CALL = /^([A-Za-z_$][\w$]*)\(\s*\)$/;
/** `obj.methode` — ex. `_.template`, on retiendra `.template`. */
const MEMBER = /^[\w$]+\.([A-Za-z_$][\w$]*)$/;

/**
 * Repère, dans le texte d'un avis, ce qu'il faudra chercher dans le code.
 * Les avis GitHub décrivent les API touchées entre backticks : c'est ce qu'on exploite.
 */
export function extractProbe(pkg: string, summary: string, details: string): TriageProbe {
  const text = `${summary}\n${details}`;
  const subpaths = new Set<string>();
  const symbols = new Set<string>();

  for (const m of text.matchAll(/`([^`\n]{2,80})`/g)) {
    const raw = m[1].trim();

    // Sous-chemin d'import du paquet : `better-auth/plugins/mcp`
    if (raw.startsWith(`${pkg}/`) && /^[\w@./-]+$/.test(raw)) {
      const last = raw.split('/').pop() ?? '';
      // `better-auth/plugins` désigne le dossier de TOUS les plugins : le code
      // l'importe pour n'importe lequel d'entre eux. Seul un module précis
      // constitue une preuve.
      if (!CONTAINER_SEGMENT.has(last.toLowerCase())) {
        subpaths.add(raw);
        if (last.length >= 3 && !NOISE.has(last)) symbols.add(last);
      }
      continue;
    }

    const call = raw.match(CALL);
    if (call && call[1].length >= 3 && !NOISE.has(call[1].toLowerCase())) {
      symbols.add(call[1]);
      continue;
    }

    const member = raw.match(MEMBER);
    if (member && member[1].length >= 3 && !NOISE.has(member[1].toLowerCase())) {
      symbols.add(member[1]);
    }
  }

  return { pkg, subpaths: [...subpaths], symbols: [...symbols] };
}

// ---------------------------------------------------------------------------
// Preuves relevées dans le code
// ---------------------------------------------------------------------------

export interface CodeEvidence {
  /** Paquets importés quelque part dans les sources. */
  packages: Set<string>;
  /** Spécificateurs d'import complets. */
  specifiers: Set<string>;
  /**
   * Symboles trouvés, indexés par paquet.
   *
   * Le rattachement au paquet est essentiel : `deleteMany` cité par un avis
   * better-auth existe aussi chez Prisma. Un symbole n'est retenu que s'il
   * apparaît dans un fichier qui importe le paquet concerné.
   */
  symbolsByPackage: Map<string, Set<string>>;
  /** true si aucun fichier source analysable n'a été trouvé (verdicts non fiables). */
  noSources: boolean;
}

export function emptyEvidence(): CodeEvidence {
  return {
    packages: new Set(),
    specifiers: new Set(),
    symbolsByPackage: new Map(),
    noSources: true,
  };
}

// ---------------------------------------------------------------------------
// Verdicts
// ---------------------------------------------------------------------------

/**
 * Triage d'une vulnérabilité de dépendance.
 * `isDirect` : le paquet est déclaré dans un manifeste (vs tiré en transitif).
 */
export function triageDependency(
  probe: TriageProbe | undefined,
  evidence: CodeEvidence,
  isDirect: boolean
): Triage {
  const reasons: string[] = [];

  // Sans sources analysables, on ne peut rien affirmer.
  if (evidence.noSources) {
    return { verdict: 'a-verifier', reasons: ['Aucune source analysable : atteignabilité non évaluée.'] };
  }

  const imported = probe ? evidence.packages.has(probe.pkg) : false;

  if (!imported) {
    reasons.push(
      isDirect
        ? 'Paquet déclaré mais jamais importé dans les sources analysées.'
        : 'Dépendance transitive, jamais importée dans les sources analysées.'
    );
    // Un paquet peut servir hors code applicatif (build, CLI, runtime) : on n'exclut rien.
    reasons.push('Un usage hors code applicatif (outil de build, CLI) resterait invisible ici.');
    return { verdict: 'improbable', reasons };
  }

  reasons.push(`Paquet importé dans le code (${probe?.pkg}).`);

  const subpaths = probe?.subpaths ?? [];
  // Seuls les symboles distinctifs peuvent trancher ; les termes courants
  // ne servent qu'à nuancer.
  const distinctive = (probe?.symbols ?? []).filter(isDistinctiveSymbol);
  const generic = (probe?.symbols ?? []).filter((s) => !isDistinctiveSymbol(s));

  const found = evidence.symbolsByPackage.get(probe?.pkg ?? '') ?? new Set<string>();
  const usedSubpaths = subpaths.filter((s) => evidence.specifiers.has(s));
  const usedDistinctive = distinctive.filter((s) => found.has(s));

  if (usedSubpaths.length > 0 || usedDistinctive.length > 0) {
    reasons.push(
      `API vulnérable présente dans le code : ${[...usedSubpaths, ...usedDistinctive].join(', ')}.`
    );
    return { verdict: 'probable', reasons };
  }

  const signals = [...subpaths, ...distinctive];
  if (signals.length > 0) {
    reasons.push(`Aucune trace de l'API vulnérable (${signals.slice(0, 6).join(', ')}) dans le code.`);
    return { verdict: 'improbable', reasons };
  }

  reasons.push(
    generic.length > 0
      ? `L'avis ne cite que des termes trop courants (${generic.slice(0, 5).join(', ')}) pour conclure.`
      : "L'avis ne nomme pas d'API précise : impossible de trancher automatiquement."
  );
  return { verdict: 'a-verifier', reasons };
}

/** Emplacements où un secret ou un motif de code n'a pas la même portée qu'en production. */
const NON_PROD_PATH =
  /(^|[\\/])(tests?|__tests__|__mocks__|spec|specs|fixtures?|examples?|samples?|mocks?|docs?|demo|e2e|cypress|storybook)([\\/]|$)/i;
const NON_PROD_FILE = /\.(test|spec|example|sample|mock|stories|fixture)\.[\w]+$|\.md$/i;

/**
 * Triage d'un finding trouvé dans un fichier (secret, SAST, conformité).
 * Le chemin renseigne sur la portée réelle : un secret dans une fixture de test
 * n'a pas le même poids que le même secret dans le code de production.
 */
export function triageFileFinding(finding: Finding): Triage {
  const file = finding.file ?? '';

  if (NON_PROD_PATH.test(file) || NON_PROD_FILE.test(file)) {
    return {
      verdict: 'improbable',
      reasons: [
        'Emplacement de test, fixture, exemple ou documentation — pas de chemin de production.',
        'À traiter quand même si la valeur est un vrai secret : elle reste dans l\'historique Git.',
      ],
    };
  }

  return { verdict: 'probable', reasons: ['Fichier de production.'] };
}

/** Ordre d'affichage : ce qui est exploitable d'abord. */
export const VERDICT_ORDER: Array<Triage['verdict']> = ['probable', 'a-verifier', 'improbable'];

export const VERDICT_LABEL: Record<Triage['verdict'], string> = {
  probable: 'Exploitable',
  'a-verifier': 'À vérifier',
  improbable: 'Aucun chemin détecté',
};
