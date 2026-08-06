import * as vscode from 'vscode';
import {
  dedupeDeps,
  dirOf,
  parseCargoToml,
  parseComposerLock,
  parseGemfileLock,
  parseGoMod,
  parseGradle,
  parseNugetLock,
  parsePackageJson,
  parsePackageLock,
  parsePipfileLock,
  parsePnpmLock,
  parsePom,
  parsePyproject,
  parseRequirements,
  parseTomlPackageBlocks,
  parseYarnLock,
  parseBunLock,
  parsePackageJsonDeclarations,
  Declaration,
  ParsedDep,
} from './parsers';

export type { Ecosystem, ParsedDep, Declaration } from './parsers';

/** Nombre max de dépendances interrogées (protège contre les monorepos géants). */
export const MAX_DEPS = 3000;

export interface CollectResult {
  deps: ParsedDep[];
  /** Nombre de dépendances ignorées faute de place (MAX_DEPS). */
  dropped: number;
  /** true si au moins une version vient d'un range et non d'un lockfile. */
  hasImprecise: boolean;
  /** Déclarations des manifestes : direct/transitif et divergences de ranges. */
  declarations: Declaration[];
}

/**
 * Collecte les dépendances du workspace.
 * Les lockfiles (versions réellement installées) ont priorité sur les manifestes
 * (ranges) : pour un même dossier, le manifeste n'est lu que s'il n'y a pas de lock.
 */
export async function collectDependencies(exclude: string[]): Promise<CollectResult> {
  const excludePattern = `{${exclude.map((e) => `**/${e}/**`).join(',')}}`;
  const found: ParsedDep[] = [];
  const declarations: Declaration[] = [];

  /**
   * Dossiers où un lockfile a fourni les versions exactes.
   * Un lockfile couvre TOUT son sous-arbre : dans un monorepo, le lock est à la
   * racine et les manifestes des workspaces (apps/*) ne doivent pas être relus
   * en mode « range », sous peine de versions fantômes.
   */
  const lockedDirs: Array<{ eco: string; dir: string }> = [];
  const lock = (eco: string, rel: string): void => {
    lockedDirs.push({ eco, dir: dirOf(rel) });
  };
  const isLocked = (eco: string, rel: string): boolean => {
    const dir = dirOf(rel);
    return lockedDirs.some(
      (l) => l.eco === eco && (l.dir === '' || dir === l.dir || dir.startsWith(`${l.dir}/`))
    );
  };

  const eachFile = async (
    glob: string,
    limit: number,
    parse: (rel: string, text: string) => ParsedDep[]
  ): Promise<void> => {
    const uris = await vscode.workspace.findFiles(glob, excludePattern, limit);
    for (const uri of uris) {
      try {
        const rel = vscode.workspace.asRelativePath(uri);
        const text = Buffer.from(await vscode.workspace.fs.readFile(uri)).toString('utf8');
        found.push(...parse(rel, text));
      } catch {
        // fichier illisible ou malformé — ignoré
      }
    }
  };

  // --- 1. Lockfiles JS (prioritaires) ---
  await eachFile('**/package-lock.json', 30, (rel, text) => {
    lock('npm', rel);
    return parsePackageLock(JSON.parse(text), rel);
  });
  await eachFile('**/yarn.lock', 30, (rel, text) => {
    lock('npm', rel);
    return parseYarnLock(text, rel);
  });
  await eachFile('**/pnpm-lock.yaml', 30, (rel, text) => {
    lock('npm', rel);
    return parsePnpmLock(text, rel);
  });
  await eachFile('**/bun.lock', 30, (rel, text) => {
    lock('npm', rel);
    return parseBunLock(text, rel);
  });

  // --- 2. Lockfiles Rust / Python / Ruby / PHP / .NET ---
  await eachFile('**/Cargo.lock', 20, (rel, text) => {
    lock('crates.io', rel);
    return parseTomlPackageBlocks(text, rel, 'crates.io');
  });
  await eachFile('**/poetry.lock', 20, (rel, text) => {
    lock('PyPI', rel);
    return parseTomlPackageBlocks(text, rel, 'PyPI');
  });
  await eachFile('**/uv.lock', 20, (rel, text) => {
    lock('PyPI', rel);
    return parseTomlPackageBlocks(text, rel, 'PyPI');
  });
  await eachFile('**/Pipfile.lock', 20, (rel, text) => {
    lock('PyPI', rel);
    return parsePipfileLock(JSON.parse(text), rel);
  });
  await eachFile('**/Gemfile.lock', 20, (rel, text) => parseGemfileLock(text, rel));
  await eachFile('**/composer.lock', 20, (rel, text) => {
    lock('Packagist', rel);
    return parseComposerLock(JSON.parse(text), rel);
  });
  await eachFile('**/packages.lock.json', 20, (rel, text) => {
    lock('NuGet', rel);
    return parseNugetLock(JSON.parse(text), rel);
  });

  // --- 3. Manifestes (seulement là où aucun lockfile n'a répondu) ---
  await eachFile('**/package.json', 50, (rel, text) => {
    const json = JSON.parse(text);
    // Les déclarations sont relevées dans tous les cas : elles disent ce qui est
    // direct et permettent de comparer les ranges entre workspaces.
    declarations.push(...parsePackageJsonDeclarations(json, rel));
    return isLocked('npm', rel) ? [] : parsePackageJson(json, rel);
  });
  await eachFile('**/Cargo.toml', 20, (rel, text) =>
    isLocked('crates.io', rel) ? [] : parseCargoToml(text, rel)
  );
  // requirements*.txt épingle des versions exactes : lu même à côté d'un lock,
  // il n'introduit pas de version fantôme. pyproject.toml ne donne que des
  // ranges, donc uniquement là où aucun lockfile Python n'a répondu.
  await eachFile('**/requirements*.txt', 20, (rel, text) => parseRequirements(text, rel));
  await eachFile('**/pyproject.toml', 20, (rel, text) =>
    isLocked('PyPI', rel) ? [] : parsePyproject(text, rel)
  );
  await eachFile('**/go.mod', 20, (rel, text) => parseGoMod(text, rel));
  await eachFile('**/pom.xml', 20, (rel, text) => parsePom(text, rel));
  await eachFile('**/build.gradle', 20, (rel, text) => parseGradle(text, rel));
  await eachFile('**/build.gradle.kts', 20, (rel, text) => parseGradle(text, rel));

  const all = dedupeDeps(found);
  const deps = all.slice(0, MAX_DEPS);
  return {
    deps,
    dropped: all.length - deps.length,
    hasImprecise: deps.some((d) => d.imprecise),
    declarations,
  };
}
