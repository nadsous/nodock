import * as vscode from 'vscode';
import { Finding, ScanReport, Severity } from './types';
import { resolveWorkspaceFile } from './paths';
import { VERDICT_LABEL } from './triage';

const DIAGNOSTIC_SEVERITY: Record<Severity, vscode.DiagnosticSeverity> = {
  critical: vscode.DiagnosticSeverity.Error,
  high: vscode.DiagnosticSeverity.Error,
  medium: vscode.DiagnosticSeverity.Warning,
  low: vscode.DiagnosticSeverity.Information,
  info: vscode.DiagnosticSeverity.Hint,
};

/** Première ligne (1-indexée) où apparaît le nom du paquet dans un manifeste. */
function findPackageLine(text: string, pkg: string): number {
  const needle = `"${pkg}"`;
  const lines = text.split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    if (lines[i].includes(needle) || lines[i].includes(pkg)) return i + 1;
  }
  return 1;
}

function messageFor(f: Finding): string {
  const parts = [f.title];
  if (f.fixedVersion) parts.push(`Corrigé dans ${f.fixedVersion}.`);
  // La description RGPD contient les exigences par juridiction : trop longue ici.
  const desc = f.kind === 'rgpd' ? f.description.split('\n')[0] : f.description;
  if (desc) parts.push(desc);
  if (f.triage) {
    parts.push(`[${VERDICT_LABEL[f.triage.verdict]}] ${f.triage.reasons.join(' ')}`);
  }
  return parts.join('\n');
}

/** Un cran plus bas : Erreur → Avertissement → Information. */
function downgrade(s: vscode.DiagnosticSeverity): vscode.DiagnosticSeverity {
  if (s === vscode.DiagnosticSeverity.Error) return vscode.DiagnosticSeverity.Warning;
  if (s === vscode.DiagnosticSeverity.Warning) return vscode.DiagnosticSeverity.Information;
  return s;
}

function toDiagnostic(f: Finding, line: number, downgradeUnreachable: boolean): vscode.Diagnostic {
  // Sans colonne connue, on souligne la ligne entière : VS Code borne à sa longueur réelle.
  const range = new vscode.Range(
    Math.max(0, line - 1),
    0,
    Math.max(0, line - 1),
    Number.MAX_SAFE_INTEGER
  );

  let severity = DIAGNOSTIC_SEVERITY[f.severity];
  // Aucun chemin de code détecté : on rétrograde plutôt que de masquer, pour que
  // l'alerte reste visible sans noyer les problèmes réellement atteignables.
  if (downgradeUnreachable && f.triage?.verdict === 'improbable') {
    severity = downgrade(severity);
  }

  const diag = new vscode.Diagnostic(range, messageFor(f), severity);
  diag.source = 'Nodock';
  // Un `code` avec cible rend l'identifiant cliquable vers l'avis de sécurité.
  diag.code = f.url && f.id ? { value: f.id, target: vscode.Uri.parse(f.url) } : f.id;
  return diag;
}

/**
 * Publie les findings du rapport dans l'onglet « Problèmes » et souligne les
 * lignes concernées dans l'éditeur.
 */
export async function publishDiagnostics(
  collection: vscode.DiagnosticCollection,
  report: ScanReport,
  downgradeUnreachable = true
): Promise<void> {
  collection.clear();

  // Regroupement par fichier pour ne lire chaque document qu'une fois.
  const byFile = new Map<string, Finding[]>();
  for (const f of report.findings) {
    if (!f.file) continue; // checklist juridique : aucun emplacement
    const list = byFile.get(f.file);
    if (list) list.push(f);
    else byFile.set(f.file, [f]);
  }

  for (const [file, findings] of byFile) {
    const uri = await resolveWorkspaceFile(file);
    if (!uri) continue;

    // Les vulnérabilités de dépendances n'ont pas de ligne : on la retrouve
    // en cherchant le nom du paquet dans le manifeste ou le lockfile.
    const needsLookup = findings.some((f) => !f.line && f.package);
    let text = '';
    if (needsLookup) {
      try {
        text = Buffer.from(await vscode.workspace.fs.readFile(uri)).toString('utf8');
      } catch {
        text = '';
      }
    }

    const diagnostics = findings.map((f) => {
      const line = f.line ?? (f.package && text ? findPackageLine(text, f.package) : 1);
      return toDiagnostic(f, line, downgradeUnreachable);
    });

    collection.set(uri, diagnostics);
  }
}
