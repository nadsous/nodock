import { Finding } from './types';

/**
 * SBOM au format CycloneDX 1.5.
 *
 * L'inventaire logiciel est de plus en plus exigé dans les appels d'offres et
 * par la réglementation (Cyber Resilience Act côté UE, décret 14028 côté US).
 * Le produire coûte peu ici : les lockfiles sont déjà lus, et les
 * vulnérabilités déjà rattachées à leur paquet.
 */

/** Nom d'écosystème OSV → type de purl. */
const PURL_TYPE: Record<string, string> = {
  npm: 'npm',
  PyPI: 'pypi',
  'crates.io': 'cargo',
  Go: 'golang',
  Maven: 'maven',
  RubyGems: 'gem',
};

export interface SbomComponent {
  name: string;
  version: string;
  ecosystem: string;
}

/** Identifiant de paquet normalisé (Package URL). */
export function toPurl(component: SbomComponent): string {
  const type = PURL_TYPE[component.ecosystem] ?? 'generic';
  if (type === 'maven' && component.name.includes(':')) {
    const [group, artifact] = component.name.split(':');
    return `pkg:maven/${group}/${artifact}@${component.version}`;
  }
  // Le scope npm garde son slash ; le reste est encodé.
  const name = component.name.startsWith('@')
    ? component.name.replace('/', '%2F')
    : encodeURIComponent(component.name);
  return `pkg:${type}/${name}@${component.version}`;
}

const SEVERITY_TO_CYCLONEDX: Record<string, string> = {
  critical: 'critical',
  high: 'high',
  medium: 'medium',
  low: 'low',
  info: 'info',
};

/**
 * Produit un document CycloneDX 1.5 : composants installés et, pour chacun,
 * les vulnérabilités connues avec leur état d'analyse.
 */
export function toCycloneDx(
  components: SbomComponent[],
  findings: Finding[],
  meta: { name: string; version: string } = { name: 'nodock-scan', version: '1.0.0' }
): object {
  const seen = new Set<string>();
  const uniqueComponents = components.filter((c) => {
    const purl = toPurl(c);
    if (seen.has(purl)) return false;
    seen.add(purl);
    return true;
  });

  const vulnerable = findings.filter((f) => f.kind === 'dependency' && f.package && f.id);

  return {
    bomFormat: 'CycloneDX',
    specVersion: '1.5',
    version: 1,
    metadata: {
      timestamp: new Date().toISOString(),
      tools: [{ vendor: 'Nodock', name: 'Nodock', version: '0.6.0-alpha' }],
      component: { type: 'application', name: meta.name, version: meta.version },
    },
    components: uniqueComponents.map((c) => ({
      type: 'library',
      name: c.name,
      version: c.version,
      purl: toPurl(c),
      scope: 'required',
    })),
    vulnerabilities: vulnerable.map((f) => ({
      id: f.id,
      source: { name: 'OSV', url: f.url },
      ratings: [
        {
          severity: SEVERITY_TO_CYCLONEDX[f.severity] ?? 'unknown',
          method: f.cvss ? 'CVSSv3' : 'other',
          ...(f.cvss ? { score: Number(f.cvss.replace(/[^\d.]/g, '')) } : {}),
        },
      ],
      description: f.title,
      affects: [{ ref: toPurl({ name: f.package!, version: f.version ?? '', ecosystem: 'npm' }) }],
      ...(f.cwe
        ? { cwes: f.cwe.split(',').map((c) => Number(c.trim().replace(/\D/g, ''))).filter(Boolean) }
        : {}),
      // Le triage Nodock s'exprime dans le vocabulaire CycloneDX.
      ...(f.triage
        ? {
            analysis: {
              state:
                f.triage.verdict === 'improbable'
                  ? 'not_affected'
                  : f.triage.verdict === 'probable'
                    ? 'exploitable'
                    : 'in_triage',
              ...(f.triage.verdict === 'improbable'
                ? { justification: 'code_not_reachable' }
                : {}),
              detail: f.triage.reasons.join(' '),
            },
          }
        : {}),
      ...(f.fixedVersion ? { recommendation: `Mettre à jour vers ${f.fixedVersion}` } : {}),
    })),
  };
}
