/**
 * Parseurs de manifestes et de lockfiles.
 *
 * Ce module est volontairement pur (aucun import `vscode`, aucune I/O) pour
 * rester testable par un simple `node --test`.
 */

export type Ecosystem =
  | 'npm'
  | 'PyPI'
  | 'crates.io'
  | 'Go'
  | 'Maven'
  | 'RubyGems'
  | 'Packagist'
  | 'NuGet';

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

/**
 * Nom PyPI canonique (PEP 503) : minuscules, `_` et `.` unifiés en `-`.
 * OSV interroge les paquets sous cette forme, et c'est elle qui permet de
 * rapprocher un `Flask` déclaré dans un manifeste du `flask` d'un lockfile.
 */
export function normalizePyPI(name: string): string {
  return name.trim().toLowerCase().replace(/[-_.]+/g, '-');
}

export function parseRequirements(text: string, file: string): ParsedDep[] {
  const deps: ParsedDep[] = [];
  for (const line of text.split(/\r?\n/)) {
    const m = line.match(/^\s*([A-Za-z0-9_.\-]+)\s*==\s*([0-9][\w.]*)/);
    if (m) deps.push({ name: normalizePyPI(m[1]), version: m[2], ecosystem: 'PyPI', file });
  }
  return deps;
}

// ---------------------------------------------------------------------------
// pyproject.toml — le manifeste des projets Python modernes (FastAPI, uv,
// Poetry, Hatch). Sans lui, un projet sans requirements.txt n'expose aucune
// dépendance à analyser.
// ---------------------------------------------------------------------------

/** Sections Poetry déclarant des dépendances (`clé = version`). */
const POETRY_DEPS =
  /^tool\.poetry\.(dependencies|dev-dependencies|group\.[\w.-]+\.dependencies)$/;

/** Retire un commentaire TOML de fin de ligne, sans toucher aux dièses cités. */
function stripTomlComment(line: string): string {
  let quote: string | null = null;
  for (let i = 0; i < line.length; i++) {
    const c = line[i];
    if (quote) {
      if (c === quote) quote = null;
    } else if (c === '"' || c === "'") {
      quote = c;
    } else if (c === '#') {
      return line.slice(0, i);
    }
  }
  return line;
}

/** Solde des crochets d'une ligne, hors chaînes (un tableau peut être multiligne). */
function bracketDelta(line: string): number {
  let quote: string | null = null;
  let depth = 0;
  for (const c of line) {
    if (quote) {
      if (c === quote) quote = null;
    } else if (c === '"' || c === "'") {
      quote = c;
    } else if (c === '[') {
      depth++;
    } else if (c === ']') {
      depth--;
    }
  }
  return depth;
}

/**
 * Version testable depuis un spécificateur PEP 440.
 * Les clauses d'exclusion sont retirées d'abord : dans `!=1.5.0,>=1.4`, prendre
 * 1.5.0 désignerait précisément la version que le projet refuse d'installer.
 */
function versionFromSpecifier(spec: string): { version: string; imprecise: boolean } | null {
  const exact = spec.match(/^\s*===?\s*([0-9][\w.]*)\s*$/);
  if (exact) return { version: exact[1], imprecise: false };

  const kept = spec
    .split(',')
    .filter((c) => !/^\s*!=/.test(c))
    .join(',');
  const version = versionFromRange(kept);
  return version ? { version, imprecise: true } : null;
}

/**
 * Exigence PEP 508 : `fastapi[all]>=0.110,<1 ; python_version >= "3.10"`.
 * Retourne null pour les dépendances sans version testable (URL directe,
 * chemin local, contrainte ouverte).
 */
function parsePep508(req: string, file: string): ParsedDep | null {
  const cleaned = req.split(';')[0].trim();
  const m = cleaned.match(/^([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*(.*)$/);
  if (!m) return null;
  // `pkg @ https://…` épingle une archive : aucune version PyPI à interroger.
  if (m[2].trim().startsWith('@')) return null;

  const name = normalizePyPI(m[1]);
  if (name === 'python') return null;
  const found = versionFromSpecifier(m[2]);
  if (!found) return null;
  return {
    name,
    version: found.version,
    ecosystem: 'PyPI',
    file,
    ...(found.imprecise ? { imprecise: true as const } : {}),
  };
}

/** pyproject.toml — dépendances PEP 621, groupes PEP 735 et sections Poetry. */
export function parsePyproject(text: string, file: string): ParsedDep[] {
  const deps: ParsedDep[] = [];
  const seen = new Set<string>();
  const push = (dep: ParsedDep | null): void => {
    if (!dep) return;
    const key = `${dep.name}|${dep.version}`;
    if (seen.has(key)) return;
    seen.add(key);
    deps.push(dep);
  };

  /** Contenu d'un tableau : chaque chaîne citée est une exigence PEP 508. */
  const pushArray = (arrayText: string): void => {
    for (const m of arrayText.matchAll(/["']([^"']+)["']/g)) push(parsePep508(m[1], file));
  };

  let section = '';
  let pending = '';
  let depth = 0;

  for (const raw of text.split(/\r?\n/)) {
    const line = stripTomlComment(raw);

    // Tableau étalé sur plusieurs lignes : on accumule jusqu'à la fermeture.
    if (depth > 0) {
      pending += `\n${line}`;
      depth += bracketDelta(line);
      if (depth <= 0) {
        pushArray(pending);
        pending = '';
        depth = 0;
      }
      continue;
    }

    const header = line.match(/^\s*\[([^\]]+)\]\s*$/);
    if (header) {
      section = header[1].trim();
      continue;
    }

    const assign = line.match(/^\s*(?:"([^"]+)"|([A-Za-z0-9][\w.-]*))\s*=\s*(.*)$/);
    if (!assign) continue;
    const key = assign[1] ?? assign[2];
    const value = assign[3].trim();

    // --- Tableaux d'exigences : PEP 621 et PEP 735 ---
    const isRequirementArray =
      (section === 'project' && key === 'dependencies') ||
      section === 'project.optional-dependencies' ||
      section === 'dependency-groups';

    if (isRequirementArray && value.startsWith('[')) {
      const delta = bracketDelta(value);
      if (delta <= 0) {
        pushArray(value);
      } else {
        pending = value;
        depth = delta;
      }
      continue;
    }

    // --- Poetry : `fastapi = "^0.110.0"` ou `{ version = "…", extras = […] }` ---
    if (POETRY_DEPS.test(section)) {
      const spec = value.startsWith('{')
        ? value.match(/version\s*=\s*["']([^"']+)["']/)?.[1]
        : value.match(/^["']([^"']+)["']/)?.[1];
      if (!spec) continue; // dépendance locale, git ou sans contrainte

      const name = normalizePyPI(key);
      if (name === 'python') continue;

      // En Poetry une version nue (`"1.2.3"`) est une égalité, pas un range.
      if (/^\d[\w.]*$/.test(spec)) {
        push({ name, version: spec, ecosystem: 'PyPI', file });
      } else {
        const found = versionFromSpecifier(spec);
        if (found) push({ name, version: found.version, ecosystem: 'PyPI', file, imprecise: true });
      }
    }
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

// ---------------------------------------------------------------------------
// Lockfiles JSON (composer.lock, Pipfile.lock, packages.lock.json)
// ---------------------------------------------------------------------------

/** composer.lock (PHP) — `packages` et `packages-dev`, versions épinglées. */
export function parseComposerLock(json: unknown, file: string): ParsedDep[] {
  const deps: ParsedDep[] = [];
  const doc = json as {
    packages?: Array<{ name?: string; version?: string }>;
    'packages-dev'?: Array<{ name?: string; version?: string }>;
  };
  for (const section of ['packages', 'packages-dev'] as const) {
    for (const entry of doc?.[section] ?? []) {
      if (!entry?.name || !entry?.version) continue;
      // La version peut porter un préfixe 'v' que Packagist/OSV n'attend pas.
      deps.push({
        name: entry.name.toLowerCase(),
        version: entry.version.replace(/^v/i, ''),
        ecosystem: 'Packagist',
        file,
      });
    }
  }
  return deps;
}

/** Pipfile.lock — `default` et `develop`, versions '==1.2.3'. */
export function parsePipfileLock(json: unknown, file: string): ParsedDep[] {
  const deps: ParsedDep[] = [];
  const doc = json as {
    default?: Record<string, { version?: string }>;
    develop?: Record<string, { version?: string }>;
  };
  for (const section of ['default', 'develop'] as const) {
    for (const [name, entry] of Object.entries(doc?.[section] ?? {})) {
      const version = entry?.version?.replace(/^==/, '');
      if (version && /^[0-9]/.test(version)) {
        deps.push({ name, version, ecosystem: 'PyPI', file });
      }
    }
  }
  return deps;
}

/** packages.lock.json (NuGet) — dépendances regroupées par target framework. */
export function parseNugetLock(json: unknown, file: string): ParsedDep[] {
  const deps: ParsedDep[] = [];
  const doc = json as {
    dependencies?: Record<string, Record<string, { resolved?: string; type?: string }>>;
  };
  for (const target of Object.values(doc?.dependencies ?? {})) {
    for (const [name, entry] of Object.entries(target)) {
      if (entry?.resolved && /^[0-9]/.test(entry.resolved)) {
        deps.push({ name, version: entry.resolved, ecosystem: 'NuGet', file });
      }
    }
  }
  return deps;
}

// ---------------------------------------------------------------------------
// Gradle (manifeste, pas de lockfile répandu → versions de ranges, imprécis)
// ---------------------------------------------------------------------------

/** build.gradle / build.gradle.kts — notations 'groupe:artefact:version'. */
export function parseGradle(text: string, file: string): ParsedDep[] {
  const deps: ParsedDep[] = [];
  const re =
    /(?:^|\s)(?:implementation|api|compileOnly|runtimeOnly|testImplementation|testRuntimeOnly|annotationProcessor|kapt|classpath|compile)\s*\(?\s*["']([\w.-]+):([\w.-]+):([0-9][\w.+-]*)["']/gm;
  for (const m of text.matchAll(re)) {
    deps.push({
      name: `${m[1]}:${m[2]}`,
      version: m[3],
      ecosystem: 'Maven',
      file,
      imprecise: true,
    });
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
