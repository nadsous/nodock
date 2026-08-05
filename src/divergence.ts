import { Finding } from './types';
import { Declaration, ParsedDep } from './parsers';

/**
 * Incohérences de versions dans un monorepo.
 *
 * Deux workspaces qui déclarent des ranges différents pour le même paquet, ou
 * deux versions réellement installées côte à côte, divergent en silence à la
 * première montée de version — et un correctif de sécurité appliqué d'un côté
 * ne protège pas l'autre.
 */

/** Normalise un range pour la comparaison : "^1.6.1" et " ^1.6.1 " sont identiques. */
function normalizeRange(range: string): string {
  return range.trim();
}

/** Ranges déclarés de façon divergente pour un même paquet. */
export function detectRangeDivergence(declarations: Declaration[]): Finding[] {
  const byName = new Map<string, Declaration[]>();
  for (const d of declarations) {
    const list = byName.get(d.name);
    if (list) list.push(d);
    else byName.set(d.name, [d]);
  }

  const findings: Finding[] = [];
  for (const [name, decls] of byName) {
    const ranges = new Set(decls.map((d) => normalizeRange(d.range)));
    if (ranges.size < 2) continue;

    const detail = decls
      .map((d) => `- \`${d.range}\` dans ${d.file}`)
      .join('\n');

    findings.push({
      kind: 'dependency',
      severity: 'low',
      id: 'NDK-DEP-001',
      title: `${name} : ranges déclarés divergents (${[...ranges].join(' / ')})`,
      description:
        `Le paquet \`${name}\` est déclaré avec des ranges différents selon les workspaces :\n${detail}\n\n` +
        'Les deux peuvent résoudre sur la même version aujourd\'hui et diverger à la prochaine ' +
        'installation. Un correctif de sécurité appliqué d\'un côté ne couvrirait pas l\'autre. ' +
        'Alignez les ranges (ou utilisez un catalogue / des overrides).',
      file: decls[0].file,
      package: name,
      triage: {
        verdict: 'a-verifier',
        reasons: ['Divergence de déclaration : à aligner même si les versions résolues coïncident.'],
      },
    });
  }

  return findings;
}

/**
 * Plusieurs versions du même paquet réellement installées.
 *
 * Restreint aux dépendances DIRECTES : dans n'importe quel arbre npm/bun, des
 * dizaines de paquets transitifs coexistent en plusieurs versions sans que le
 * développeur puisse — ni doive — y faire quoi que ce soit. Les signaler
 * noierait le rapport.
 */
export function detectDuplicateInstalls(deps: ParsedDep[], directNames: Set<string>): Finding[] {
  const byKey = new Map<string, Set<string>>();
  const fileByKey = new Map<string, string>();

  for (const d of deps) {
    if (d.imprecise) continue; // versions déduites d'un range : comparaison sans valeur
    if (!directNames.has(d.name)) continue;
    const key = `${d.ecosystem}|${d.name}`;
    const versions = byKey.get(key);
    if (versions) versions.add(d.version);
    else {
      byKey.set(key, new Set([d.version]));
      fileByKey.set(key, d.file);
    }
  }

  const findings: Finding[] = [];
  for (const [key, versions] of byKey) {
    if (versions.size < 2) continue;
    const [ecosystem, name] = key.split('|');
    const sorted = [...versions].sort();

    findings.push({
      kind: 'dependency',
      severity: 'low',
      id: 'NDK-DEP-002',
      title: `${name} : ${versions.size} versions installées (${sorted.join(', ')})`,
      description:
        `Plusieurs versions de \`${name}\` (${ecosystem}) coexistent dans l'arbre de dépendances : ` +
        `${sorted.join(', ')}.\n\n` +
        'Monter une seule des copies laisse les autres vulnérables, et deux copies d\'une ' +
        'bibliothèque à état (client HTTP, ORM, runtime de composants) peuvent se comporter ' +
        'différemment. Dédupliquez si possible.',
      file: fileByKey.get(key),
      package: name,
      triage: {
        verdict: 'a-verifier',
        reasons: ['Duplication fréquente en npm ; sérieuse pour les bibliothèques à état ou de sécurité.'],
      },
    });
  }

  return findings;
}
