import * as vscode from 'vscode';
import { getWebviewHtml } from './webview';
import { scanDependencies } from './sca';
import { scanWorkspaceFiles } from './scanner';
import { legalChecklistFindings } from './rgpd';
import { generateLegalNotice } from './legal';
import { exportReport } from './report';
import { fetchNews } from './feed';
import { publishDiagnostics } from './diagnostics';
import { resolveWorkspaceFile } from './paths';
import { applyIgnoreRules, parseIgnoreFile, IgnoreRule } from './ignore';
import {
  CodeEvidence,
  emptyEvidence,
  triageDependency,
  triageFileFinding,
  VERDICT_ORDER,
} from './triage';
import { Finding, ScanReport, SEVERITY_ORDER } from './types';

class NodockPanelProvider implements vscode.WebviewViewProvider {
  private view?: vscode.WebviewView;
  private lastReport?: ScanReport;
  private scanning = false;

  constructor(
    private readonly context: vscode.ExtensionContext,
    private readonly diagnostics: vscode.DiagnosticCollection
  ) {}

  resolveWebviewView(view: vscode.WebviewView): void {
    this.view = view;
    view.webview.options = { enableScripts: true };
    const nonce = createNonce();
    view.webview.html = getWebviewHtml(view.webview, nonce);

    view.webview.onDidReceiveMessage(async (msg) => {
      switch (msg.command) {
        case 'scan':
          await this.runScan();
          break;
        case 'refreshNews':
          await this.refreshNews();
          break;
        case 'exportReport':
          await this.exportLastReport();
          break;
        case 'legalNotice':
          await generateLegalNotice();
          break;
        case 'openUrl':
          await openExternal(msg.url);
          break;
        case 'openFile':
          await openWorkspaceFile(msg.file, msg.line);
          break;
        case 'ready':
          // Le webview vient d'être (re)construit : on lui rend le dernier rapport.
          if (this.lastReport) this.post({ type: 'report', report: this.lastReport });
          break;
      }
    });
  }

  private post(message: unknown): void {
    this.view?.webview.postMessage(message);
  }

  private config() {
    const cfg = vscode.workspace.getConfiguration('nodock');
    return {
      exclude: cfg.get<string[]>('excludeFolders', []),
      maxFileSizeKB: cfg.get<number>('maxFileSizeKB', 512),
      maxFiles: cfg.get<number>('maxFiles', 5000),
      rssFeeds: cfg.get<string[]>('rssFeeds', []),
      showInProblems: cfg.get<boolean>('showInProblems', true),
      downgradeUnreachable: cfg.get<boolean>('downgradeUnreachable', true),
    };
  }

  async runScan(): Promise<void> {
    if (!vscode.workspace.workspaceFolders) {
      this.post({ type: 'scanError', error: 'Ouvrez d\'abord un dossier dans VS Code.' });
      return;
    }
    if (this.scanning) return;
    this.scanning = true;

    const { exclude, maxFileSizeKB, maxFiles } = this.config();
    this.post({ type: 'scanStart', step: 'Démarrage du scan…' });

    try {
      const report = await vscode.window.withProgress(
        {
          location: vscode.ProgressLocation.Notification,
          title: 'Nodock — scan de sécurité',
          cancellable: true,
        },
        async (progress, token) => {
          const step = (message: string): void => {
            progress.report({ message });
            this.post({ type: 'scanStep', step: message });
          };

          const findings: Finding[] = [];
          const notes: string[] = [];
          let dependenciesScanned = 0;
          let installed = new Map<string, string>();
          let components: Array<{ name: string; version: string; ecosystem: string }> = [];

          // --- Dépendances (réseau) ---
          // Isolé : une panne de l'API OSV ne doit pas emporter le reste du scan.
          step('Analyse des dépendances (OSV.dev)…');
          try {
            const sca = await scanDependencies({ exclude, token, onProgress: step });
            findings.push(...sca.findings);
            notes.push(...sca.notes);
            dependenciesScanned = sca.scanned;
            installed = sca.installed;
            components = sca.components;
          } catch (err) {
            notes.push(`Analyse des dépendances indisponible : ${errorMessage(err)}`);
          }

          // --- Fichiers : secrets + SAST + conformité en un seul passage ---
          // Les sondes issues des avis sont recherchées pendant cette lecture,
          // pour savoir si le code atteint réellement les API vulnérables.
          step('Analyse des fichiers (secrets, code, conformité)…');
          let filesScanned = 0;
          let evidence: CodeEvidence = emptyEvidence();
          try {
            const files = await scanWorkspaceFiles({
              exclude,
              maxFileSizeKB,
              maxFiles,
              probes: findings.map((f) => f.probe).filter((p) => p !== undefined),
              installed,
              token,
              onProgress: step,
            });
            findings.push(...files.findings);
            notes.push(...files.notes);
            filesScanned = files.filesScanned;
            evidence = files.evidence;
          } catch (err) {
            notes.push(`Analyse des fichiers interrompue : ${errorMessage(err)}`);
          }

          // --- Triage : ce finding concerne-t-il réellement ce projet ? ---
          step('Triage des résultats…');
          for (const f of findings) {
            if (f.triage) continue; // déjà tranché (cohérence de l'arbre de dépendances)
            f.triage =
              f.kind === 'dependency'
                ? triageDependency(f.probe, evidence, f.direct ?? false)
                : triageFileFinding(f);
          }

          // --- Baseline : faux positifs déjà arbitrés par l'équipe ---
          const ignoreRules = await loadIgnoreRules();
          const filtered = applyIgnoreRules(findings, ignoreRules);
          findings.length = 0;
          findings.push(...filtered.kept);
          if (filtered.ignored > 0) {
            notes.push(`${filtered.ignored} finding(s) masqué(s) par .nodockignore.`);
          }

          findings.push(...legalChecklistFindings());

          // Ordre = ce qu'il faut traiter en premier : d'abord l'actionnable
          // (exploitable > à vérifier > aucun chemin détecté), puis la sévérité.
          // La checklist juridique, purement informative, ferme la marche.
          const rank = (f: Finding): number[] => [
            f.severity === 'info' ? 1 : 0,
            VERDICT_ORDER.indexOf(f.triage?.verdict ?? 'a-verifier'),
            SEVERITY_ORDER.indexOf(f.severity),
          ];
          findings.sort((a, b) => {
            const [ra, rb] = [rank(a), rank(b)];
            return ra[0] - rb[0] || ra[1] - rb[1] || ra[2] - rb[2];
          });

          const count = (s: string): number =>
            findings.filter((f) => f.severity === s).length;

          return {
            generatedAt: new Date().toISOString(),
            findings,
            stats: {
              dependenciesScanned,
              filesScanned,
              critical: count('critical'),
              high: count('high'),
              medium: count('medium'),
              low: count('low'),
            },
            notes,
            cancelled: token.isCancellationRequested,
            components,
          } satisfies ScanReport;
        }
      );

      this.lastReport = report;
      this.post({ type: 'report', report });

      const { showInProblems, downgradeUnreachable } = this.config();
      if (showInProblems) {
        await publishDiagnostics(this.diagnostics, report, downgradeUnreachable);
      } else {
        this.diagnostics.clear();
      }

      if (report.cancelled) {
        vscode.window.showInformationMessage('Nodock : scan annulé — résultats partiels affichés.');
      } else if (report.stats.critical > 0) {
        vscode.window.showWarningMessage(
          `Nodock : ${report.stats.critical} vulnérabilité(s) critique(s) détectée(s) !`
        );
      } else {
        const problems = report.stats.high;
        if (problems > 0) {
          vscode.window.showInformationMessage(`Nodock : ${problems} problème(s) à corriger.`);
        }
      }
    } catch (err) {
      this.post({ type: 'scanError', error: `Erreur pendant le scan : ${errorMessage(err)}` });
    } finally {
      this.scanning = false;
    }
  }

  async exportLastReport(): Promise<void> {
    if (!this.lastReport) {
      vscode.window.showWarningMessage('Nodock : lancez d\'abord un scan.');
      return;
    }
    await exportReport(this.lastReport);
  }

  async refreshNews(): Promise<void> {
    this.post({ type: 'newsStart' });
    try {
      const { rssFeeds } = this.config();
      const { items, errors } = await fetchNews(rssFeeds);
      this.post({ type: 'news', items, errors });
    } catch (err) {
      this.post({ type: 'news', items: [], errors: [errorMessage(err)] });
    }
  }
}

/** Charge la baseline `.nodockignore` à la racine de chaque dossier du workspace. */
async function loadIgnoreRules(): Promise<IgnoreRule[]> {
  const rules: IgnoreRule[] = [];
  for (const folder of vscode.workspace.workspaceFolders ?? []) {
    try {
      const uri = vscode.Uri.joinPath(folder.uri, '.nodockignore');
      const text = Buffer.from(await vscode.workspace.fs.readFile(uri)).toString('utf8');
      rules.push(...parseIgnoreFile(text));
    } catch {
      // Pas de baseline dans ce dossier — cas normal.
    }
  }
  return rules;
}

function errorMessage(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

function createNonce(): string {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  const bytes = new Uint8Array(32);
  globalThis.crypto.getRandomValues(bytes);
  return Array.from(bytes, (b) => chars[b % chars.length]).join('');
}

/** N'ouvre que du http(s) : les URL viennent de sources externes (OSV, flux RSS). */
async function openExternal(rawUrl: unknown): Promise<void> {
  if (typeof rawUrl !== 'string') return;
  let parsed: vscode.Uri;
  try {
    parsed = vscode.Uri.parse(rawUrl, true);
  } catch {
    return;
  }
  if (parsed.scheme !== 'http' && parsed.scheme !== 'https') {
    vscode.window.showWarningMessage(`Nodock : lien ignoré (protocole non autorisé) — ${rawUrl}`);
    return;
  }
  await vscode.env.openExternal(parsed);
}

/** Ouvre un chemin relatif du rapport, en cherchant dans tous les dossiers du workspace. */
async function openWorkspaceFile(file: unknown, line?: unknown): Promise<void> {
  if (typeof file !== 'string') return;

  const uri = await resolveWorkspaceFile(file);
  if (!uri) {
    vscode.window.showWarningMessage(`Nodock : fichier introuvable — ${file}`);
    return;
  }

  const editor = await vscode.window.showTextDocument(
    await vscode.workspace.openTextDocument(uri)
  );
  if (typeof line === 'number' && line > 0) {
    const pos = new vscode.Position(line - 1, 0);
    editor.selection = new vscode.Selection(pos, pos);
    editor.revealRange(new vscode.Range(pos, pos), vscode.TextEditorRevealType.InCenter);
  }
}

export function activate(context: vscode.ExtensionContext): void {
  const diagnostics = vscode.languages.createDiagnosticCollection('nodock');
  const provider = new NodockPanelProvider(context, diagnostics);

  context.subscriptions.push(
    diagnostics,
    vscode.window.registerWebviewViewProvider('nodock.panel', provider),
    vscode.commands.registerCommand('nodock.scan', async () => {
      await vscode.commands.executeCommand('nodock.panel.focus');
      await provider.runScan();
    }),
    vscode.commands.registerCommand('nodock.refreshNews', () => provider.refreshNews()),
    vscode.commands.registerCommand('nodock.exportReport', () => provider.exportLastReport()),
    vscode.commands.registerCommand('nodock.legalNotice', () => generateLegalNotice())
  );
}

export function deactivate(): void {}
