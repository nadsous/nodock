import * as vscode from 'vscode';
import { Finding, Severity } from './types';
import { collectDependencies, Declaration, MAX_DEPS, ParsedDep } from './lockfiles';
import { cvss3BaseScore, severityFromScore } from './cvss';
import { extractProbe } from './triage';
import { detectDuplicateInstalls, detectRangeDivergence } from './divergence';

/** Réponse de /v1/vulns/{id} — le détail complet d'une vulnérabilité OSV. */
interface OsvVuln {
  id: string;
  summary?: string;
  details?: string;
  aliases?: string[];
  database_specific?: { severity?: string; cwe_ids?: string[] };
  severity?: Array<{ type: string; score: string }>;
  affected?: Array<{
    package?: { name?: string; ecosystem?: string };
    ranges?: Array<{ events?: Array<{ introduced?: string; fixed?: string }> }>;
  }>;
  references?: Array<{ type?: string; url: string }>;
}

const OSV_BATCH_URL = 'https://api.osv.dev/v1/querybatch';
const OSV_VULN_URL = 'https://api.osv.dev/v1/vulns/';
const BATCH_SIZE = 100;
const HYDRATE_CONCURRENCY = 8;
/** Au-delà, on n'enrichit plus : le rapport reste lisible sans noyer l'API. */
const MAX_HYDRATED = 300;

/** Cache des détails OSV pour la durée de la session (les avis changent rarement). */
const vulnCache = new Map<string, OsvVuln>();

// ---------------------------------------------------------------------------
// Sévérité
// ---------------------------------------------------------------------------

/**
 * Sévérité d'une vulnérabilité, par ordre de fiabilité décroissante :
 * score CVSS calculé → sévérité déclarée par la base → heuristique textuelle.
 */
export function mapSeverity(v: OsvVuln): { severity: Severity; cvss?: string } {
  const vector = v.severity?.find((s) => s.type === 'CVSS_V3')?.score;
  if (vector) {
    const score = cvss3BaseScore(vector);
    if (score !== null) {
      return { severity: severityFromScore(score), cvss: `CVSS ${score.toFixed(1)}` };
    }
  }

  const declared = v.database_specific?.severity?.toLowerCase();
  if (declared === 'critical') return { severity: 'critical' };
  if (declared === 'high') return { severity: 'high' };
  if (declared === 'moderate' || declared === 'medium') return { severity: 'medium' };
  if (declared === 'low') return { severity: 'low' };

  const txt = `${v.summary ?? ''} ${v.details ?? ''}`.toLowerCase();
  if (/remote code execution|\brce\b|arbitrary code/.test(txt)) return { severity: 'critical' };
  if (/sql injection|path traversal|prototype pollution|deserialization/.test(txt)) {
    return { severity: 'high' };
  }
  return { severity: 'medium' };
}

/** Version corrigée, en ne regardant que le paquet réellement concerné. */
function extractFixed(v: OsvVuln, dep: ParsedDep): string | undefined {
  const candidates = (v.affected ?? []).filter(
    (a) => !a.package?.name || a.package.name.toLowerCase() === dep.name.toLowerCase()
  );
  for (const a of candidates.length > 0 ? candidates : v.affected ?? []) {
    for (const r of a.ranges ?? []) {
      for (const e of r.events ?? []) {
        if (e.fixed) return e.fixed;
      }
    }
  }
  return undefined;
}

/**
 * CVE à afficher. Un avis peut porter plusieurs alias CVE : on privilégie celui
 * que référence l'avis officiel, pour que l'identifiant et le lien concordent.
 */
function primaryCve(v: OsvVuln): string | undefined {
  const cves = (v.aliases ?? []).filter((a) => a.startsWith('CVE-'));
  if (cves.length === 0) return undefined;
  const advisory = v.references?.find((r) => r.type === 'ADVISORY')?.url ?? '';
  return cves.find((c) => advisory.includes(c)) ?? cves[0];
}

function bestUrl(v: OsvVuln, cve?: string): string {
  const advisory = v.references?.find((r) => r.type === 'ADVISORY')?.url;
  if (advisory) return advisory;
  if (cve) return `https://nvd.nist.gov/vuln/detail/${cve}`;
  return `https://osv.dev/vulnerability/${v.id}`;
}

// ---------------------------------------------------------------------------
// Appels réseau
// ---------------------------------------------------------------------------

async function fetchJson(url: string, init?: RequestInit): Promise<unknown> {
  const res = await fetch(url, init);
  if (!res.ok) throw new Error(`OSV a répondu ${res.status} (${url})`);
  return res.json();
}

/**
 * Récupère le détail des vulnérabilités.
 * /v1/querybatch ne renvoie que { id, modified } : sans cet appel, on n'a
 * ni résumé, ni sévérité, ni version corrigée.
 */
async function hydrate(ids: string[], token?: vscode.CancellationToken): Promise<void> {
  const todo = ids.filter((id) => !vulnCache.has(id)).slice(0, MAX_HYDRATED);
  let cursor = 0;

  const worker = async (): Promise<void> => {
    while (cursor < todo.length && !token?.isCancellationRequested) {
      const id = todo[cursor++];
      try {
        vulnCache.set(id, (await fetchJson(OSV_VULN_URL + id)) as OsvVuln);
      } catch {
        // détail indisponible — on retombera sur un finding dégradé
      }
    }
  };

  await Promise.all(
    Array.from({ length: Math.min(HYDRATE_CONCURRENCY, todo.length) }, worker)
  );
}

export interface ScaResult {
  findings: Finding[];
  scanned: number;
  /** Avertissements non bloquants à afficher (imprécision, troncature…). */
  notes: string[];
  /** Versions installées (nom → version), pour conditionner les règles de normes. */
  installed: Map<string, string>;
  /** Inventaire complet, pour l'export SBOM. */
  components: Array<{ name: string; version: string; ecosystem: string }>;
}

/** Findings de dépendances sans avis de sécurité : cohérence de l'arbre. */
function hygieneFindings(deps: ParsedDep[], declarations: Declaration[]): Finding[] {
  const directNames = new Set(declarations.map((d) => d.name));
  return [
    ...detectRangeDivergence(declarations),
    ...detectDuplicateInstalls(deps, directNames),
  ];
}

/** Interroge l'API OSV.dev (gratuite, sans clé) puis enrichit chaque vulnérabilité. */
export async function scanDependencies(opts: {
  exclude: string[];
  token?: vscode.CancellationToken;
  onProgress?: (message: string) => void;
}): Promise<ScaResult> {
  const { exclude, token, onProgress } = opts;
  const { deps, dropped, hasImprecise, declarations } = await collectDependencies(exclude);
  const notes: string[] = [];
  const directNames = new Set(declarations.map((d) => d.name));

  if (dropped > 0) {
    notes.push(`${dropped} dépendances au-delà de la limite de ${MAX_DEPS} n'ont pas été analysées.`);
  }
  if (hasImprecise) {
    notes.push(
      'Certaines versions proviennent de ranges (^1.2.3) faute de lockfile — résultats approximatifs.'
    );
  }
  // La plus haute version installée fait foi pour les règles de normes.
  const installed = new Map<string, string>();
  for (const d of deps) {
    const current = installed.get(d.name);
    if (!current || d.version.localeCompare(current, undefined, { numeric: true }) > 0) {
      installed.set(d.name, d.version);
    }
  }

  const components = deps.map((d) => ({ name: d.name, version: d.version, ecosystem: d.ecosystem }));

  if (deps.length === 0) return { findings: [], scanned: 0, notes, installed, components };

  const hygiene = hygieneFindings(deps, declarations);

  // --- 1. Quelles dépendances sont vulnérables ? ---
  const hits: Array<{ dep: ParsedDep; ids: string[] }> = [];
  for (let i = 0; i < deps.length; i += BATCH_SIZE) {
    if (token?.isCancellationRequested) break;
    const batch = deps.slice(i, i + BATCH_SIZE);
    onProgress?.(
      `Dépendances : ${Math.min(i + BATCH_SIZE, deps.length)}/${deps.length} vérifiées…`
    );

    const data = (await fetchJson(OSV_BATCH_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        queries: batch.map((d) => ({
          package: { name: d.name, ecosystem: d.ecosystem },
          version: d.version,
        })),
      }),
    })) as { results?: Array<{ vulns?: Array<{ id: string }> }> };

    (data.results ?? []).forEach((r, idx) => {
      const ids = (r.vulns ?? []).map((v) => v.id);
      if (ids.length > 0) hits.push({ dep: batch[idx], ids });
    });
  }

  // --- 2. Détail de chaque vulnérabilité trouvée ---
  const uniqueIds = [...new Set(hits.flatMap((h) => h.ids))];
  if (uniqueIds.length > 0) {
    onProgress?.(`Récupération de ${uniqueIds.length} avis de sécurité…`);
    await hydrate(uniqueIds, token);
  }
  if (uniqueIds.length > MAX_HYDRATED) {
    notes.push(
      `${uniqueIds.length - MAX_HYDRATED} avis n'ont pas été détaillés (limite de ${MAX_HYDRATED}).`
    );
  }

  // --- 3. Construction des findings ---
  const findings: Finding[] = [...hygiene];
  for (const { dep, ids } of hits) {
    for (const id of ids) {
      const v = vulnCache.get(id);
      if (!v) {
        // Détail indisponible : on signale quand même la vulnérabilité.
        findings.push({
          kind: 'dependency',
          severity: 'medium',
          id,
          title: `${dep.name}@${dep.version} — ${id}`,
          description: 'Détail de la vulnérabilité non récupéré. Ouvrez le lien pour le consulter.',
          file: dep.file,
          package: dep.name,
          version: dep.version,
          ecosystem: dep.ecosystem,
          imprecise: dep.imprecise,
          direct: directNames.has(dep.name),
          url: `https://osv.dev/vulnerability/${id}`,
        });
        continue;
      }
      const cve = primaryCve(v);
      const { severity, cvss } = mapSeverity(v);
      findings.push({
        kind: 'dependency',
        severity,
        id: cve ?? v.id,
        title: `${dep.name}@${dep.version} — ${v.summary ?? v.id}`,
        description: (v.details ?? v.summary ?? '').slice(0, 800),
        file: dep.file,
        package: dep.name,
        version: dep.version,
        ecosystem: dep.ecosystem,
        fixedVersion: extractFixed(v, dep),
        imprecise: dep.imprecise,
        cvss,
        cwe: v.database_specific?.cwe_ids?.join(', '),
        direct: directNames.has(dep.name),
        // Ce que le code devra contenir pour que la faille soit atteignable.
        probe: extractProbe(dep.name, v.summary ?? '', v.details ?? ''),
        url: bestUrl(v, cve),
      });
    }
  }

  return { findings, scanned: deps.length, notes, installed, components };
}
