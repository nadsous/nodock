import { Severity } from './types';

/**
 * Calcul du score de base CVSS v3.x (spec 3.1, §7.1).
 * Module pur : aucune dépendance à `vscode`, donc testable hors VS Code.
 */

const WEIGHTS: Record<string, Record<string, number>> = {
  AV: { N: 0.85, A: 0.62, L: 0.55, P: 0.2 },
  AC: { L: 0.77, H: 0.44 },
  UI: { N: 0.85, R: 0.62 },
  C: { H: 0.56, L: 0.22, N: 0 },
  I: { H: 0.56, L: 0.22, N: 0 },
  A: { H: 0.56, L: 0.22, N: 0 },
};

/** Les privilèges requis pèsent différemment selon que le scope change ou non. */
const PR_UNCHANGED: Record<string, number> = { N: 0.85, L: 0.62, H: 0.27 };
const PR_CHANGED: Record<string, number> = { N: 0.85, L: 0.68, H: 0.5 };

/** Arrondi supérieur au dixième, tel que défini par la spec CVSS v3.1. */
function roundUp(n: number): number {
  return Math.ceil(n * 10) / 10;
}

/** Score de base CVSS v3.x depuis un vecteur. Retourne null si le vecteur est illisible. */
export function cvss3BaseScore(vector: string): number | null {
  const parts = new Map<string, string>();
  for (const chunk of vector.split('/')) {
    const [k, v] = chunk.split(':');
    if (k && v) parts.set(k, v);
  }

  const weight = (k: string): number | null => {
    const raw = parts.get(k);
    const w = raw ? WEIGHTS[k]?.[raw] : undefined;
    return w === undefined ? null : w;
  };

  const scope = parts.get('S');
  const pr = parts.get('PR');
  if (!scope || !pr) return null;
  const prWeight = (scope === 'C' ? PR_CHANGED : PR_UNCHANGED)[pr];
  if (prWeight === undefined) return null;

  const av = weight('AV');
  const ac = weight('AC');
  const ui = weight('UI');
  const c = weight('C');
  const i = weight('I');
  const a = weight('A');
  if (av === null || ac === null || ui === null || c === null || i === null || a === null) {
    return null;
  }

  const iss = 1 - (1 - c) * (1 - i) * (1 - a);
  const impact =
    scope === 'C' ? 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15) : 6.42 * iss;
  if (impact <= 0) return 0;

  const exploitability = 8.22 * av * ac * prWeight * ui;
  const base = scope === 'C' ? 1.08 * (impact + exploitability) : impact + exploitability;
  return roundUp(Math.min(base, 10));
}

export function severityFromScore(score: number): Severity {
  if (score >= 9) return 'critical';
  if (score >= 7) return 'high';
  if (score >= 4) return 'medium';
  return 'low';
}
