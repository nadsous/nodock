import * as vscode from 'vscode';
import { Finding, TriageProbe } from './types';
import { SECRET_FILE_TYPES, scanSecretsInText } from './secrets';
import { SAST_FILE_TYPES, scanCodeInText } from './sast';
import { RGPD_FILE_TYPES, scanRgpdInText, aggregateCompliance } from './rgpd';
import { extractImports } from './imports';
import { CodeEvidence, emptyEvidence } from './triage';
import { isGeneratedPath, shouldSkipGenerated } from './generated';
import {
  aggregateStandards,
  applicableRules,
  scanStandardsInText,
  STANDARDS_FILE_TYPES,
} from './standards';
import {
  AUDIT_FILE_TYPES,
  auditFindings,
  collectAuditSignals,
  emptySignals,
} from './audit';
import { INFRA_FILE_TYPES, scanInfraInText } from './infra';
import { aggregateAttack, ATTACK_FILE_TYPES, scanAttackInText } from './attack';
import { aggregateWebSec, WEBSEC_FILE_TYPES, scanWebSecInText } from './websec';

export interface FileScanResult {
  findings: Finding[];
  filesScanned: number;
  notes: string[];
  /** Preuves d'usage relevées dans le code, pour le triage des dépendances. */
  evidence: CodeEvidence;
}

/** Fichiers dans lesquels chercher les imports (code applicatif). */
const SOURCE_FILES = /\.([jt]sx?|mjs|cjs|vue|svelte|py)$/i;

/** Garde-fou : au-delà, la recherche de symboles coûterait plus qu'elle ne rapporte. */
const MAX_SYMBOLS = 200;

/**
 * Plafond de findings par règle et par fichier. Les règles génériques
 * (http://, debug: true) matchent parfois des centaines de lignes : sans plafond
 * elles noient le rapport.
 */
const MAX_PER_RULE_PER_FILE = 5;

/** Fréquence de remontée de la progression (en fichiers). */
const PROGRESS_EVERY = 25;

function capPerRule(findings: Finding[], relPath: string): Finding[] {
  const counts = new Map<string, number>();
  const kept: Finding[] = [];

  for (const f of findings) {
    const key = `${f.kind}|${f.id}`;
    const n = (counts.get(key) ?? 0) + 1;
    counts.set(key, n);
    if (n <= MAX_PER_RULE_PER_FILE) kept.push(f);
  }

  for (const [key, n] of counts) {
    if (n <= MAX_PER_RULE_PER_FILE) continue;
    const sample = kept.find((f) => `${f.kind}|${f.id}` === key);
    if (sample) {
      sample.description += `\n\n(+ ${n - MAX_PER_RULE_PER_FILE} autre(s) occurrence(s) dans ${relPath})`;
    }
  }

  return kept;
}

/**
 * Parcourt le workspace UNE seule fois et applique les règles secrets, SAST et
 * conformité à chaque fichier. Chaque fichier n'est lu et décodé qu'une fois.
 */
export async function scanWorkspaceFiles(opts: {
  exclude: string[];
  maxFileSizeKB: number;
  maxFiles: number;
  /** API vulnérables à rechercher, issues des avis de sécurité. */
  probes?: TriageProbe[];
  /** Versions installées, pour n'activer que les règles de normes pertinentes. */
  installed?: Map<string, string>;
  token?: vscode.CancellationToken;
  onProgress?: (message: string) => void;
}): Promise<FileScanResult> {
  const {
    exclude,
    maxFileSizeKB,
    maxFiles,
    probes = [],
    installed = new Map<string, string>(),
    token,
    onProgress,
  } = opts;

  // Règles de normes retenues selon les versions réellement installées.
  const standardRules = applicableRules(installed);

  // Sondes indexées par paquet : on ne cherche les symboles d'un avis que dans
  // les fichiers qui importent le paquet visé.
  const probesByPackage = new Map<string, string[]>();
  let budget = MAX_SYMBOLS;
  for (const p of probes) {
    if (budget <= 0) break;
    const existing = probesByPackage.get(p.pkg) ?? [];
    const merged = [...new Set([...existing, ...p.symbols])].slice(0, budget);
    budget -= merged.length - existing.length;
    probesByPackage.set(p.pkg, merged);
  }
  const evidence: CodeEvidence = emptyEvidence();
  const excludePattern = `{${exclude.map((e) => `**/${e}/**`).join(',')}}`;

  // On demande une entrée de plus que la limite pour détecter la troncature.
  const uris = await vscode.workspace.findFiles('**/*', excludePattern, maxFiles + 1);
  const notes: string[] = [];
  const truncated = uris.length > maxFiles;
  if (truncated) {
    notes.push(
      `Plus de ${maxFiles} fichiers dans le workspace : seuls les ${maxFiles} premiers ont été analysés (réglage nodock.maxFiles).`
    );
  }

  const targets = uris.slice(0, maxFiles).filter(
    (u) =>
      // Les sorties de build sont écartées avant même d'être lues : elles ne
      // contiennent pas de code qu'on édite, et un bundle répète le même motif
      // dans chaque chunk.
      !isGeneratedPath(u.fsPath) &&
      (SECRET_FILE_TYPES.test(u.fsPath) ||
        SAST_FILE_TYPES.test(u.fsPath) ||
        RGPD_FILE_TYPES.test(u.fsPath) ||
        STANDARDS_FILE_TYPES.test(u.fsPath) ||
        AUDIT_FILE_TYPES.test(u.fsPath) ||
        WEBSEC_FILE_TYPES.test(u.fsPath) ||
        INFRA_FILE_TYPES.test(u.fsPath) ||
        ATTACK_FILE_TYPES.test(u.fsPath))
  );

  const findings: Finding[] = [];
  // Signaux de posture, accumulés sur tout le projet : les protections absentes
  // ne se voient qu'une fois l'ensemble parcouru.
  const auditSignals = emptySignals();
  let filesScanned = 0;
  let skippedTooBig = 0;
  let skippedGenerated = uris.slice(0, maxFiles).filter((u) => isGeneratedPath(u.fsPath)).length;

  for (let i = 0; i < targets.length; i++) {
    if (token?.isCancellationRequested) {
      notes.push('Scan des fichiers interrompu.');
      break;
    }
    const uri = targets[i];

    if (i % PROGRESS_EVERY === 0) {
      onProgress?.(`Fichiers : ${i}/${targets.length} analysés…`);
    }

    try {
      const stat = await vscode.workspace.fs.stat(uri);
      if (stat.size > maxFileSizeKB * 1024) {
        skippedTooBig++;
        continue;
      }

      const text = Buffer.from(await vscode.workspace.fs.readFile(uri)).toString('utf8');

      // Second filet : un bundle ou un fichier généré peut se trouver n'importe où.
      if (shouldSkipGenerated(uri.fsPath, text)) {
        skippedGenerated++;
        continue;
      }

      const rel = vscode.workspace.asRelativePath(uri);
      filesScanned++;

      // --- Preuves d'usage (même lecture, aucun coût d'I/O supplémentaire) ---
      if (SOURCE_FILES.test(uri.fsPath)) {
        evidence.noSources = false;
        const { specifiers, packages } = extractImports(uri.fsPath, text);
        for (const s of specifiers) evidence.specifiers.add(s);
        for (const p of packages) evidence.packages.add(p);

        // Un symbole ne compte que dans un fichier important le paquet visé :
        // sinon `deleteMany` (Prisma) validerait une CVE de better-auth.
        for (const pkg of packages) {
          const symbols = probesByPackage.get(pkg);
          if (!symbols) continue;
          let hits = evidence.symbolsByPackage.get(pkg);
          if (!hits) {
            hits = new Set<string>();
            evidence.symbolsByPackage.set(pkg, hits);
          }
          for (const symbol of symbols) {
            if (!hits.has(symbol) && text.includes(symbol)) hits.add(symbol);
          }
        }
      }

      if (AUDIT_FILE_TYPES.test(uri.fsPath)) {
        collectAuditSignals(uri.fsPath, rel, text, auditSignals);
      }

      const perFile: Finding[] = [];
      if (SECRET_FILE_TYPES.test(uri.fsPath)) perFile.push(...scanSecretsInText(text, rel));
      if (SAST_FILE_TYPES.test(uri.fsPath)) perFile.push(...scanCodeInText(uri.fsPath, rel, text));
      if (RGPD_FILE_TYPES.test(uri.fsPath)) perFile.push(...scanRgpdInText(uri.fsPath, rel, text));
      if (WEBSEC_FILE_TYPES.test(uri.fsPath)) {
        perFile.push(...scanWebSecInText(uri.fsPath, rel, text));
      }
      if (INFRA_FILE_TYPES.test(uri.fsPath)) {
        perFile.push(...scanInfraInText(uri.fsPath, rel, text));
      }
      if (ATTACK_FILE_TYPES.test(uri.fsPath)) {
        perFile.push(...scanAttackInText(uri.fsPath, rel, text));
      }
      if (standardRules.length > 0 && STANDARDS_FILE_TYPES.test(uri.fsPath)) {
        perFile.push(...scanStandardsInText(uri.fsPath, rel, text, standardRules));
      }

      findings.push(...capPerRule(perFile, rel));
    } catch {
      // fichier illisible (binaire, permissions, lien cassé) — ignoré
    }
  }

  if (skippedGenerated > 0) {
    notes.push(
      `${skippedGenerated} fichier(s) généré(s) ou minifié(s) ignoré(s) (sorties de build, bundles).`
    );
  }
  if (skippedTooBig > 0) {
    notes.push(
      `${skippedTooBig} fichier(s) ignoré(s) car plus gros que ${maxFileSizeKB} Ko (réglage nodock.maxFileSizeKB).`
    );
  }

  // Conformité et migrations se raisonnent à l'échelle du projet, pas du fichier.
  const compliance = findings.filter((f) => f.kind === 'rgpd');
  const standards = findings.filter((f) => f.kind === 'standards');
  const websec = findings.filter((f) => f.kind === 'websec');
  const attack = findings.filter((f) => f.kind === 'attack');
  const rest = findings.filter(
    (f) =>
      f.kind !== 'rgpd' &&
      f.kind !== 'standards' &&
      f.kind !== 'websec' &&
      f.kind !== 'attack'
  );

  return {
    findings: [
      ...rest,
      ...auditFindings(auditSignals),
      ...aggregateAttack(attack),
      ...aggregateWebSec(websec),
      ...aggregateStandards(standards),
      ...aggregateCompliance(compliance),
    ],
    filesScanned,
    notes,
    evidence,
  };
}
