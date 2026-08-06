import * as vscode from 'vscode';
import { ScanReport, Severity } from './types';
import { toCycloneDx } from './sbom';

const SARIF_LEVEL: Record<Severity, string> = {
  critical: 'error',
  high: 'error',
  medium: 'warning',
  low: 'note',
  info: 'note',
};

/** Convertit un rapport Nodock au format SARIF 2.1.0 (compatible GitHub Code Scanning). */
export function toSarif(report: ScanReport): object {
  return {
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: 'Nodock',
            version: '0.6.0-alpha',
            informationUri: 'https://github.com/nodock',
            rules: [
              ...new Set(report.findings.map((f) => f.id ?? 'nodock-finding')),
            ].map((id) => ({ id })),
          },
        },
        results: report.findings.map((f) => ({
          ruleId: f.id ?? 'nodock-finding',
          level: SARIF_LEVEL[f.severity],
          message: { text: `${f.title}\n${f.description}` },
          locations: f.file
            ? [
                {
                  physicalLocation: {
                    artifactLocation: { uri: f.file.replace(/\\/g, '/') },
                    region: { startLine: f.line ?? 1 },
                  },
                },
              ]
            : [],
        })),
      },
    ],
  };
}

/** Propose l'enregistrement du rapport en JSON ou SARIF. */
export async function exportReport(report: ScanReport): Promise<void> {
  const choice = await vscode.window.showQuickPick(
    [
      { label: 'JSON', description: 'Rapport brut Nodock' },
      { label: 'SARIF', description: 'Compatible GitHub Code Scanning / CI' },
      { label: 'CycloneDX', description: 'SBOM : inventaire logiciel + vulnérabilités triées' },
    ],
    { placeHolder: 'Format d\'export du rapport Nodock' }
  );
  if (!choice) return;

  const extension =
    choice.label === 'SARIF' ? 'sarif' : choice.label === 'CycloneDX' ? 'cdx.json' : 'json';

  const uri = await vscode.window.showSaveDialog({
    defaultUri: vscode.Uri.file(`nodock-report.${extension}`),
    filters:
      choice.label === 'SARIF' ? { SARIF: ['sarif'] } : { JSON: ['json'] },
  });
  if (!uri) return;

  const projectName = vscode.workspace.workspaceFolders?.[0]?.name ?? 'projet';
  const content =
    choice.label === 'SARIF'
      ? JSON.stringify(toSarif(report), null, 2)
      : choice.label === 'CycloneDX'
        ? JSON.stringify(
            toCycloneDx(report.components ?? [], report.findings, {
              name: projectName,
              version: '1.0.0',
            }),
            null,
            2
          )
        : JSON.stringify(report, null, 2);
  await vscode.workspace.fs.writeFile(uri, Buffer.from(content, 'utf8'));
  vscode.window.showInformationMessage(`Nodock : rapport exporté → ${uri.fsPath}`);
}
