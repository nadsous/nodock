import { Finding } from './types';

/**
 * Baseline de faux positifs : fichier `.nodockignore` à la racine du projet.
 *
 * Sans mécanisme de suppression, un faux positif revient à chaque scan et
 * l'outil finit par être ignoré en bloc. Le format reprend celui de
 * `.gitignore`, avec en plus la possibilité de viser une règle :
 *
 *   # commentaire
 *   src/vendor/**            → tout ce dossier
 *   CMP-009                  → cette règle, partout
 *   NDK-JS-001 src/rules/**  → cette règle, dans ces fichiers seulement
 */

export interface IgnoreRule {
  /** Identifiant de règle visé (CMP-009, NDK-JS-001, CVE-…), ou undefined = toutes. */
  ruleId?: string;
  /** Glob de chemins visé, ou undefined = tous. */
  pattern?: string;
  /** Ligne d'origine, pour pouvoir expliquer ce qui a filtré quoi. */
  source: string;
}

/** Un identifiant de règle : CMP-009, NDK-JS-001, CVE-2026-1234, GHSA-…, ou un nom de secret. */
const RULE_ID = /^(CMP-\d+|NDK-[A-Z]+-\d+|CVE-\d{4}-\d+|GHSA-[\w-]+)$/i;

/** Traduit un glob type gitignore en expression régulière. */
export function globToRegExp(glob: string): RegExp {
  const normalized = glob.replace(/\\/g, '/').replace(/^\.\//, '').replace(/^\//, '');
  let out = '';

  for (let i = 0; i < normalized.length; i++) {
    const c = normalized[i];
    if (c === '*') {
      if (normalized[i + 1] === '*') {
        // `**/` traverse les dossiers ; `**` en fin de motif prend tout le reste.
        out += '.*';
        i++;
        if (normalized[i + 1] === '/') i++;
      } else {
        out += '[^/]*';
      }
    } else if (c === '?') {
      out += '[^/]';
    } else {
      out += c.replace(/[.+^${}()|[\]\\]/g, '\\$&');
    }
  }

  // Un motif désignant un dossier couvre tout son contenu.
  if (normalized.endsWith('/')) out += '.*';
  return new RegExp(`^${out}$`, 'i');
}

/** Lit un `.nodockignore`. Les lignes vides et les commentaires sont ignorés. */
export function parseIgnoreFile(content: string): IgnoreRule[] {
  const rules: IgnoreRule[] = [];

  for (const raw of content.split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line.startsWith('#')) continue;

    const parts = line.split(/\s+/);
    if (RULE_ID.test(parts[0])) {
      rules.push({
        ruleId: parts[0].toUpperCase(),
        pattern: parts[1],
        source: line,
      });
    } else {
      rules.push({ pattern: parts[0], source: line });
    }
  }

  return rules;
}

function matchesPath(pattern: string | undefined, file: string | undefined): boolean {
  if (!pattern) return true;
  if (!file) return false;
  const normalized = file.replace(/\\/g, '/');
  const re = globToRegExp(pattern);
  if (re.test(normalized)) return true;
  // Un motif sans joker désignant un dossier couvre son contenu.
  if (!/[*?]/.test(pattern)) {
    const dir = pattern.replace(/\/$/, '');
    return normalized === dir || normalized.startsWith(`${dir}/`);
  }
  return false;
}

/** Ce finding est-il couvert par une règle de la baseline ? */
export function isIgnored(finding: Finding, rules: IgnoreRule[]): IgnoreRule | undefined {
  return rules.find((rule) => {
    if (rule.ruleId && (finding.id ?? '').toUpperCase() !== rule.ruleId) return false;
    return matchesPath(rule.pattern, finding.file);
  });
}

/** Retire les findings couverts par la baseline et indique combien l'ont été. */
export function applyIgnoreRules(
  findings: Finding[],
  rules: IgnoreRule[]
): { kept: Finding[]; ignored: number } {
  // Toujours un NOUVEAU tableau, même sans règle : renvoyer la référence
  // d'origine permettait à un appelant qui vide `findings` de détruire du même
  // coup le contenu de `kept`. Sans .nodockignore, tous les findings
  // disparaissaient — et le rapport annonçait « aucune vulnérabilité ».
  if (rules.length === 0) return { kept: [...findings], ignored: 0 };

  const kept = findings.filter((f) => !isIgnored(f, rules));
  return { kept, ignored: findings.length - kept.length };
}
