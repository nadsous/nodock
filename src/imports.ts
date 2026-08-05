/**
 * Extraction des dépendances réellement importées par le code.
 * Module pur (aucun import `vscode`) pour rester testable hors VS Code.
 */

const JS_FILES = /\.([jt]sx?|mjs|cjs|vue|svelte)$/i;
const PY_FILES = /\.py$/i;

/** import x from 'spec' | require('spec') | import('spec') | export … from 'spec' */
const JS_SPECIFIER = /(?:\bfrom|\bimport|\brequire)\s*\(?\s*['"]([^'"\n]+)['"]/g;

/** from a.b import c | import a.b, c */
const PY_FROM = /^\s*from\s+([\w.]+)\s+import\b/gm;
const PY_IMPORT = /^\s*import\s+([\w.,\s]+)$/gm;

/**
 * Nom du paquet correspondant à un spécificateur d'import.
 * 'better-auth/plugins/mcp' → 'better-auth' ; '@scope/pkg/sub' → '@scope/pkg'.
 * Retourne null pour les imports relatifs ou absolus (chemins locaux).
 */
export function packageOfSpecifier(spec: string): string | null {
  if (!spec || spec.startsWith('.') || spec.startsWith('/') || spec.startsWith('node:')) {
    return null;
  }
  const parts = spec.split('/');
  if (spec.startsWith('@')) {
    return parts.length >= 2 ? `${parts[0]}/${parts[1]}` : null;
  }
  return parts[0] || null;
}

export interface FileImports {
  /** Spécificateurs complets, ex. 'better-auth/plugins/mcp'. */
  specifiers: Set<string>;
  /** Racines de paquets, ex. 'better-auth'. */
  packages: Set<string>;
}

/** Relève les modules importés par un fichier source (JS/TS et Python). */
export function extractImports(fsPath: string, text: string): FileImports {
  const specifiers = new Set<string>();
  const packages = new Set<string>();

  const add = (spec: string): void => {
    const trimmed = spec.trim();
    if (!trimmed) return;
    specifiers.add(trimmed);
    const pkg = packageOfSpecifier(trimmed);
    if (pkg) packages.add(pkg);
  };

  if (JS_FILES.test(fsPath)) {
    for (const m of text.matchAll(JS_SPECIFIER)) add(m[1]);
  }

  if (PY_FILES.test(fsPath)) {
    for (const m of text.matchAll(PY_FROM)) add(m[1].split('.')[0]);
    for (const m of text.matchAll(PY_IMPORT)) {
      for (const mod of m[1].split(',')) {
        // "import numpy as np" → numpy
        add(mod.trim().split(/\s+/)[0].split('.')[0]);
      }
    }
  }

  return { specifiers, packages };
}
