import { Finding, Severity } from './types';

/**
 * Score de sécurité /100 du projet.
 *
 * Un finding pèse selon sa sévérité, mais MODULÉ par le verdict du triage :
 * une faille « probable » (chemin de code détecté) pèse cinq fois plus qu'une
 * faille « improbable » (aucun chemin détecté). Comparer deux scores n'a de
 * sens que si le même barème a été appliqué aux deux scans.
 *
 * Module pur (aucun import `vscode`) pour rester testable hors VS Code.
 */

const SEVERITY_WEIGHT: Record<Severity, number> = {
  critical: 25,
  high: 10,
  medium: 4,
  low: 1,
  info: 0,
};

/** Le triage reflète la confiance que la faille concerne réellement le projet. */
const VERDICT_MULTIPLIER: Record<string, number> = {
  probable: 1,
  'a-verifier': 0.6,
  improbable: 0.2,
};

/** Pénalité brute d'un finding (avant agrégation). */
export function findingWeight(f: Finding): number {
  const multiplier = f.triage ? (VERDICT_MULTIPLIER[f.triage.verdict] ?? 1) : 1;
  return SEVERITY_WEIGHT[f.severity] * multiplier;
}

/** Score global : 100 moins la somme des pénalités, borné entre 0 et 100. */
export function computeScore(findings: Finding[]): number {
  const penalty = findings.reduce((sum, f) => sum + findingWeight(f), 0);
  return Math.max(0, Math.min(100, Math.round(100 - penalty)));
}
