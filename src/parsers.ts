/**
 * Parseurs de manifestes et de lockfiles.
 *
 * Ce module est volontairement pur (aucun import `vscode`, aucune I/O) pour
 * rester testable par un simple `node --test`.
 */

export type Ecosystem = 'npm' | 'PyPI' | 'crates.io' | 'Go' | 'Maven' | 'RubyGems';

export interface ParsedDep {
  name: string;
  version: string;
  ecosystem: Ecosystem;
  file: string;
  /** true = version déduite d'un range (^1.2.3), pas de la version réellement installée. */
  imprecise?: boolean;
}

/** Dossier d'un chemin relatif, séparateurs normalisés. */
export function dirOf(relPath: string): string {
  const norm = relPath.replace(/\\/g, '/');
  const i = norm.lastIndexOf('/');
  return i === -1 ? '' : norm.slice(0, i);
}

/**
 * Déduit une version testable depuis un range semver (^1.2.3 → 1.2.3).
 * C'est la borne BASSE du range, donc imprécis : utilisé seulement en l'absence de lockfile.
 */
export function versionFromRange(range: string): string | null {
  if (/^(workspace|file|link|git|github|npm|catalog):/i.test(range.trim())) return null;
  const m = range.match(/\d+\.\d+\.\d+(?:[-+][\w.]+)?/) || range.match(/\d+\.\d+/);
  return m ? m[0] : null;
}

// ---------------------------------------------------------------------------
// Lockfiles JavaScript
// ---------------------------------------------------------------------------

/** package-lock.json (v1 comme v2/v3). */
export function parsePackageLock(json: unknown, file: string): ParsedDep[] {
  const deps: ParsedDep[] = [];
  const doc = json as {
    packages?: Record<string, { version?: string; link?: boolean }>;
    dependencies?: Record<string, { version?: string; dependencies?: unknown }>;
  };

  // v2 / v3 : map "node_modules/xxx" → { version }
  if (doc?.packages) {
    for (const [key, entry] of Object.entries(doc.packages)) {
      if (!key || entry?.link || !entry?.version) continue;
      const idx = key.lastIndexOf('node_modules/');
      if (idx === -1) continue; // paquet local du workspace, pas une dépendance publiée
      const name = key.slice(idx + 'node_modules/'.length);
      if (name) deps.push({ name, version: entry.version, ecosystem: 'npm', file });
    }
    if (deps.length > 0) return deps;
  }

  // v1 : arbre imbriqué
  const walk = (tree: Record<string, { version?: string; dependencies?: unknown }>): void => {
    for (const [name, entry] of Object.entries(tree ?? {})) {
      if (entry?.version) deps.push({ name, version: entry.version, ecosystem: 'npm', file });
      if (entry?.dependencies) {
        walk(entry.dependencies as Record<string, { version?: string; dependencies?: unknown }>);
      }
    }
  };
  if (doc?.dependencies) walk(doc.dependencies);
  return deps;
}

/** yarn.lock — format classique (v1) et Berry (v2+). */
export function parseYarnLock(text: string, file: string): ParsedDep[] {
  const deps: ParsedDep[] = [];
  // Un bloc = un en-tête en colonne 0 suivi de lignes indentées.
  for (const block of text.split(/\r?\n(?=\S)/)) {
    const header = block.split(/\r?\n/)[0];
    if (!header || header.startsWith('#') || header.startsWith('__metadata')) continue;
    // "@scope/pkg@npm:^1.0.0, @scope/pkg@^1.0.0:" → @scope/pkg
    const nameMatch = header.match(/^"?((?:@[^/"@\s]+\/)?[^@"\s]+)@/);
    // v1 : version "1.2.3"   |   Berry : version: 1.2.3
    const verMatch = block.match(/^\s+version:?\s+"?([^"\s]+)"?\s*$/m);
    if (nameMatch && verMatch) {
      deps.push({ name: nameMatch[1], version: verMatch[1], ecosystem: 'npm', file });
    }
  }
  return deps;
}

/**
 * bun.lock (Bun >= 1.2) — JSONC, donc lu au motif plutôt qu'avec JSON.parse
 * (virgules traînantes). Les entrées de `packages` ont la forme :
 *   "nom": ["nom@1.2.3", "", { … }, "sha512-…"]
 * Le nom et la version viennent du spécificateur, pas de la clé : en dépendance
 * imbriquée la clé vaut "parent/enfant".
 */
export function parseBunLock(text: string, file: string): ParsedDep[] {
  const deps: ParsedDep[] = [];
  const entry = /"(?:[^"]+)"\s*:\s*\[\s*"([^"]+)"/g;

  for (const m of text.matchAll(entry)) {
    const spec = m[1];
    const at = spec.lastIndexOf('@');
    if (at <= 0) continue;
    const name = spec.slice(0, at);
    const version = spec.slice(at + 1);
    // Écarte les workspaces locaux ("pkg@workspace:apps/x") et les alias git.
    if (!/^\d/.test(version)) continue;
    deps.push({ name, version, ecosystem: 'npm', file });
  }

  return deps;
}

/** pnpm-lock.yaml — clés `/pkg/1.2.3:`, `/pkg@1.2.3:` ou `pkg@1.2.3:` selon la version. */
export function parsePnpmLock(text: string, file: string): ParsedDep[] {
  const deps: ParsedDep[] = [];
  const re = /^\s+\/?((?:@[\w.-]+\/)?[\w.-]+)[@/](\d[\w.+-]*)(?:\([^)]*\))?:/;
  for (const line of text.split(/\r?\n/)) {
    const m = line.match(re);
    if (m) deps.push({ name: m[1], version: m[2], ecosystem: 'npm', file });
  }
  return deps;
}

// ---------------------------------------------------------------------------
// Lockfiles TOML ([[package]] : Cargo.lock, poetry.lock, uv.lock)
// ---------------------------------------------------------------------------

export function parseTomlPackageBlocks(
  text: string,
  file: string,
  ecosystem: Ecosystem
): ParsedDep[] {
  const deps: ParsedDep[] = [];
  for (const block of text.split(/\[\[package\]\]/).slice(1)) {
    const name = block.match(/^\s*name\s*=\s*"([^"]+)"/m)?.[1];
    const version = block.match(/^\s*version\s*=\s*"([^"]+)"/m)?.[1];
    if (name && version) deps.push({ name, version, ecosystem, file });
  }
  return deps;
}

// ---------------------------------------------------------------------------
// Manifestes (fallback quand aucun lockfile n'est présent)
// ---------------------------------------------------------------------------

/** Dépendance telle que DÉCLARÉE dans un manifeste (le range, pas la version résolue). */
export interface Declaration {
  name: string;
  range: string;
  file: string;
  ecosystem: Ecosystem;
}

/**
 * Déclarations d'un package.json, relevées même en présence d'un lockfile :
 * elles servent à distinguer direct/transitif et à détecter les divergences
 * de ranges entre workspaces.
 */
export function parsePackageJsonDeclarations(json: unknown, file: string): Declaration[] {
  const out: Declaration[] = [];
  const doc = json as Record<string, Record<string, string> | undefined>;
  for (const section of ['dependencies', 'devDependencies', 'peerDependencies']) {
    for (const [name, range] of Object.entries(doc?.[section] ?? {})) {
      out.push({ name, range: String(range), file, ecosystem: 'npm' });
    }
  }
  return out;
}

export function parsePackageJson(json: unknown, file: string): ParsedDep[] {
  const deps: ParsedDep[] = [];
  const doc = json as Record<string, Record<string, string> | undefined>;
  for (const section of ['dependencies', 'devDependencies']) {
    for (const [name, range] of Object.entries(doc?.[section] ?? {})) {
      const version = versionFromRange(String(range));
      if (version) deps.push({ name, version, ecosystem: 'npm', file, imprecise: true });
    }
  }
  return deps;
}

export function parseRequirements(text: string, file: string): ParsedDep[] {
  const deps: ParsedDep[] = [];
  for (const line of text.split(/\r?\n/)) {
    const m = line.match(/^\s*([A-Za-z0-9_.\-]+)\s*==\s*([0-9][\w.]*)/);
    if (m) deps.push({ name: m[1], version: m[2], ecosystem: 'PyPI', file });
  }
  return deps;
}

export function parseCargoToml(text: string, file: string): ParsedDep[] {
  const deps: ParsedDep[] = [];
  let inDeps = false;
  for (const line of text.split(/\r?\n/)) {
    const section = line.match(/^\s*\[([\w.-]+)\]/);
    if (section) {
      inDeps = /^(dev-|build-)?dependencies$/.test(section[1]);
      continue;
    }
    if (!inDeps) continue;
    const simple = line.match(/^\s*([A-Za-z0-9_-]+)\s*=\s*"([0-9][\w.]*)/);
    const inline = line.match(/^\s*([A-Za-z0-9_-]+)\s*=\s*\{[^}]*version\s*=\s*"([0-9][\w.]*)/);
    const m = simple ?? inline;
    if (m) deps.push({ name: m[1], version: m[2], ecosystem: 'crates.io', file, imprecise: true });
  }
  return deps;
}

export function parseGoMod(text: string, file: string): ParsedDep[] {
  const deps: ParsedDep[] = [];
  for (const line of text.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('module') || trimmed.startsWith('//')) continue;
    // go.mod épingle des versions exactes : "github.com/x/y v1.2.3"
    const m = trimmed.match(/^(?:require\s+)?([\w.\-/]+)\s+v([0-9][\w.\-]*)/);
    if (m) deps.push({ name: m[1], version: m[2], ecosystem: 'Go', file });
  }
  return deps;
}

export function parsePom(text: string, file: string): ParsedDep[] {
  const deps: ParsedDep[] = [];
  for (const b of text.match(/<dependency>[\s\S]*?<\/dependency>/g) ?? []) {
    const group = b.match(/<groupId>([^<]+)<\/groupId>/)?.[1];
    const artifact = b.match(/<artifactId>([^<]+)<\/artifactId>/)?.[1];
    const version = b.match(/<version>([0-9][^<]*)<\/version>/)?.[1];
    if (group && artifact && version) {
      deps.push({ name: `${group}:${artifact}`, version, ecosystem: 'Maven', file });
    }
  }
  return deps;
}

export function parseGemfileLock(text: string, file: string): ParsedDep[] {
  const deps: ParsedDep[] = [];
  for (const line of text.split(/\r?\n/)) {
    const m = line.match(/^ {4}([a-zA-Z0-9_-]+) \(([0-9][\w.]*)\)$/);
    if (m) deps.push({ name: m[1], version: m[2], ecosystem: 'RubyGems', file });
  }
  return deps;
}

/** Déduplique par écosystème/nom/version en privilégiant les versions issues d'un lockfile. */
export function dedupeDeps(found: ParsedDep[]): ParsedDep[] {
  const seen = new Map<string, ParsedDep>();
  for (const d of found) {
    const key = `${d.ecosystem}|${d.name}|${d.version}`;
    const prev = seen.get(key);
    if (!prev || (prev.imprecise && !d.imprecise)) seen.set(key, d);
  }
  return [...seen.values()];
}
