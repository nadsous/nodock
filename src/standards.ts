import { Finding, Severity } from './types';

/**
 * Normes de codage : API dépréciées ou supprimées, évaluées SELON LA VERSION
 * réellement installée.
 *
 * `ReactDOM.render` n'est un problème qu'à partir de React 18, et une erreur
 * franche en React 19. Signaler la même chose à tout le monde serait faux.
 * Chaque règle porte donc la version à partir de laquelle elle s'applique, et
 * n'est activée que si le paquet correspondant est présent dans cette version.
 */

export interface StandardRule {
  id: string;
  name: string;
  regex: RegExp;
  languages: RegExp;
  severity: Severity;
  /** Paquet concerné et version majeure à partir de laquelle la règle vaut. */
  pkg?: { name: string; sinceMajor?: number };
  /** Ce qui change, et pourquoi. */
  description: string;
  /** Le remplacement, prêt à appliquer. */
  fix: string;
  /**
   * Tâche de migration : un seul finding pour tout le projet.
   * Migrer 75 composants est une décision unique, pas 75 problèmes distincts.
   */
  migration?: boolean;
}

const JS = /\.([jt]sx?|mjs|cjs)$/i;
const JSX = /\.([jt]sx|vue|svelte)$/i;
const PY = /\.py$/i;

const RULES: StandardRule[] = [
  // --- React ---
  {
    id: 'STD-REACT-001',
    name: 'ReactDOM.render supprimé',
    // Seul l'appel compte : `import { createPortal } from "react-dom"` reste
    // parfaitement valide en React 19.
    regex: /\bReactDOM\.(render|hydrate)\s*\(/,
    languages: JS,
    severity: 'high',
    pkg: { name: 'react', sinceMajor: 18 },
    description:
      'ReactDOM.render est déprécié depuis React 18 et supprimé en React 19 : le rendu concurrent n\'est pas activé, et les Suspense/transitions ne fonctionnent pas.',
    fix: 'import { createRoot } from "react-dom/client"; createRoot(container).render(<App />);',
  },
  {
    id: 'STD-REACT-002',
    migration: true,
    name: 'propTypes supprimés',
    regex: /\.propTypes\s*=|from\s+['"]prop-types['"]/,
    languages: JS,
    severity: 'medium',
    pkg: { name: 'react', sinceMajor: 19 },
    description:
      'React 19 ignore silencieusement propTypes : les validations ne s\'exécutent plus, vous perdez le contrôle sans aucun avertissement.',
    fix: 'Passez aux types TypeScript (interface Props) — la vérification devient statique.',
  },
  {
    id: 'STD-REACT-003',
    migration: true,
    name: 'forwardRef inutile',
    regex: /\bforwardRef\s*[(<]/,
    languages: JS,
    severity: 'low',
    pkg: { name: 'react', sinceMajor: 19 },
    description:
      'Depuis React 19, ref est une prop ordinaire : forwardRef n\'a plus d\'utilité et sera déprécié.',
    fix: 'Recevez ref directement : function Input({ ref, ...props }) { … }',
  },
  {
    id: 'STD-REACT-004',
    migration: true,
    name: 'defaultProps sur composant fonction',
    regex: /\.defaultProps\s*=/,
    languages: JS,
    severity: 'medium',
    pkg: { name: 'react', sinceMajor: 19 },
    description:
      'defaultProps est supprimé pour les composants fonction en React 19 : les valeurs par défaut ne sont plus appliquées.',
    fix: 'Utilisez les paramètres par défaut : function Bouton({ taille = "md" }) { … }',
  },

  // --- Next.js ---
  {
    id: 'STD-NEXT-001',
    migration: true,
    name: 'next/head dans l\'App Router',
    regex: /from\s+['"]next\/head['"]/,
    languages: JSX,
    severity: 'medium',
    pkg: { name: 'next', sinceMajor: 13 },
    description:
      'next/head est sans effet dans l\'App Router : les balises ne sont pas injectées, ce qui casse le référencement de la page.',
    fix: 'Exportez `metadata` ou `generateMetadata()` depuis votre page/layout.',
  },
  {
    id: 'STD-NEXT-002',
    name: 'images.domains déprécié',
    regex: /images\s*:\s*\{[^}]*\bdomains\s*:/,
    languages: /next\.config\.(js|mjs|ts)$/i,
    severity: 'medium',
    pkg: { name: 'next', sinceMajor: 14 },
    description:
      'images.domains est déprécié : il autorise tous les chemins d\'un domaine, sans restriction de protocole ni de port.',
    fix: 'Passez à images.remotePatterns: [{ protocol: "https", hostname: "exemple.com", pathname: "/img/**" }].',
  },
  {
    id: 'STD-NEXT-003',
    migration: true,
    name: 'getServerSideProps / getStaticProps',
    regex: /export\s+(async\s+)?function\s+(getServerSideProps|getStaticProps|getInitialProps)\b|export\s+const\s+(getServerSideProps|getStaticProps)\b/,
    languages: JSX,
    severity: 'low',
    pkg: { name: 'next', sinceMajor: 13 },
    description:
      'Ces fonctions appartiennent au Pages Router. Dans l\'App Router elles ne sont jamais appelées — la page se rend sans données.',
    fix: 'Faites du composant serveur un `async function` et récupérez les données directement avec await.',
  },
  {
    id: 'STD-NEXT-004',
    migration: true,
    name: 'next/legacy/image',
    regex: /from\s+['"]next\/legacy\/image['"]/,
    languages: JSX,
    severity: 'low',
    pkg: { name: 'next', sinceMajor: 14 },
    description:
      'Le composant Image historique est conservé pour compatibilité mais ne bénéficie plus des optimisations récentes.',
    fix: 'Migrez vers next/image (les props layout/objectFit deviennent fill et style).',
  },

  // --- Node.js ---
  {
    id: 'STD-NODE-001',
    name: 'new Buffer() supprimé',
    regex: /new\s+Buffer\s*\(/,
    languages: JS,
    severity: 'high',
    description:
      'new Buffer() est supprimé depuis Node 22. C\'était aussi une faille : la mémoire allouée n\'était pas remise à zéro et pouvait exposer des données résiduelles.',
    fix: 'Buffer.from(donnée) pour convertir, Buffer.alloc(taille) pour allouer.',
  },
  {
    id: 'STD-NODE-002',
    name: 'url.parse() déprécié',
    regex: /\burl\.parse\s*\(|require\(['"]url['"]\)\.parse/,
    languages: JS,
    severity: 'medium',
    description:
      'url.parse() est déprécié : son analyse non standardisée a donné lieu à plusieurs contournements de sécurité (validation d\'hôte trompée).',
    fix: 'new URL(entrée, base) — l\'API WHATWG, conforme aux navigateurs.',
  },
  {
    id: 'STD-NODE-003',
    name: 'fs.exists() déprécié',
    regex: /\bfs\.exists\s*\(/,
    languages: JS,
    severity: 'low',
    description:
      'fs.exists() a une signature de callback incohérente avec le reste de l\'API et expose à une situation de compétition entre le test et l\'usage.',
    fix: 'fs.access() / fs.existsSync(), ou tentez directement l\'opération et gérez l\'erreur.',
  },
  {
    id: 'STD-NODE-004',
    migration: true,
    name: 'punycode déprécié',
    regex: /require\(['"]punycode['"]\)|from\s+['"]punycode['"]/,
    languages: JS,
    severity: 'low',
    description: 'Le module natif punycode est déprécié et sera supprimé.',
    fix: 'Installez le paquet userland `punycode.js`, ou utilisez l\'API URL native.',
  },

  // --- Python ---
  {
    id: 'STD-PY-001',
    name: 'datetime.utcnow() déprécié',
    regex: /datetime\.utcnow\s*\(|datetime\.utcfromtimestamp\s*\(/,
    languages: PY,
    severity: 'medium',
    description:
      'Déprécié depuis Python 3.12 : renvoie un datetime NAÏF présenté comme UTC, source classique de décalages horaires en production.',
    fix: 'datetime.now(datetime.UTC) — le résultat porte son fuseau.',
  },
  {
    id: 'STD-PY-002',
    name: 'module imp supprimé',
    regex: /^\s*import\s+imp\b|^\s*from\s+imp\s+import/m,
    languages: PY,
    severity: 'high',
    description: 'Le module imp est supprimé depuis Python 3.12 : l\'import lève une erreur.',
    fix: 'Utilisez importlib.',
  },
  {
    id: 'STD-PY-003',
    name: 'assert pour valider une entrée',
    regex: /^\s*assert\s+.*(request|input|argv|param|user)/im,
    languages: PY,
    severity: 'medium',
    description:
      'Les assertions disparaissent quand Python tourne avec -O : la validation s\'évapore en production, exactement là où elle compte.',
    fix: 'Levez une exception explicite : if not valide: raise ValueError(…).',
  },
];

/** Numéro de version majeur, ou null si illisible. */
function majorOf(version: string): number | null {
  const m = version.match(/^\D*(\d+)/);
  return m ? Number(m[1]) : null;
}

/**
 * Sélectionne les règles applicables au projet.
 * `installed` : nom de paquet → version, tel que lu dans les lockfiles.
 */
export function applicableRules(installed: Map<string, string>): StandardRule[] {
  return RULES.filter((rule) => {
    if (!rule.pkg) return true; // règle de plateforme (Node, Python)
    const version = installed.get(rule.pkg.name);
    if (!version) return false; // le framework n'est pas utilisé ici
    if (rule.pkg.sinceMajor === undefined) return true;
    const major = majorOf(version);
    return major !== null && major >= rule.pkg.sinceMajor;
  });
}

/**
 * Regroupe les tâches de migration en un finding par règle.
 *
 * Remplacer forwardRef dans 75 composants shadcn/ui est une décision unique,
 * exécutable d'un codemod. En faire 75 alertes noie tout le reste du rapport.
 */
export function aggregateStandards(findings: Finding[]): Finding[] {
  const byRule = new Map<string, Finding[]>();
  for (const f of findings) {
    const list = byRule.get(f.id ?? '');
    if (list) list.push(f);
    else byRule.set(f.id ?? '', [f]);
  }

  const out: Finding[] = [];
  for (const [id, group] of byRule) {
    const rule = RULES.find((r) => r.id === id);
    if (!rule?.migration || group.length === 1) {
      out.push(...group);
      continue;
    }

    const files = [...new Set(group.map((f) => f.file ?? ''))];
    const shown = files.slice(0, 8).map((f) => `• ${f}`).join('\n');
    const more = files.length > 8 ? `\n• … et ${files.length - 8} autre(s)` : '';

    out.push({
      ...group[0],
      title: `${rule.name} — ${group.length} occurrence(s) dans ${files.length} fichier(s)`,
      description:
        `${rule.description}\n\n**Correctif**\n${rule.fix}\n\n` +
        `**Migration groupée** — ${group.length} occurrence(s), à traiter en une fois :\n${shown}${more}` +
        (rule.pkg ? `\n\n_Règle active parce que ${rule.pkg.name} ≥ ${rule.pkg.sinceMajor} est installé._` : ''),
    });
  }
  return out;
}

/** Extensions susceptibles de porter une règle de normes. */
export const STANDARDS_FILE_TYPES = /\.([jt]sx?|mjs|cjs|vue|svelte|py)$/i;

const COMMENT = /^\s*(\/\/|#|\*)/;

/** Applique les règles de normes retenues au contenu d'un fichier déjà lu. */
export function scanStandardsInText(
  fsPath: string,
  relPath: string,
  text: string,
  rules: StandardRule[]
): Finding[] {
  const applicable = rules.filter((r) => r.languages.test(fsPath));
  if (applicable.length === 0) return [];

  const findings: Finding[] = [];
  const lines = text.split(/\r?\n/);

  lines.forEach((line, i) => {
    if (COMMENT.test(line)) return;
    for (const rule of applicable) {
      if (rule.regex.test(line)) {
        findings.push({
          kind: 'standards',
          severity: rule.severity,
          id: rule.id,
          title: `${rule.name} (${rule.id})`,
          description:
            `${rule.description}\n\n**Correctif**\n${rule.fix}` +
            (rule.pkg
              ? `\n\n_Règle active parce que ${rule.pkg.name} ≥ ${rule.pkg.sinceMajor} est installé._`
              : ''),
          file: relPath,
          line: i + 1,
        });
      }
    }
  });

  return findings;
}
