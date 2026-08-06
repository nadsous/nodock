/**
 * Extraction des dépendances réellement importées par le code.
 * Module pur (aucun import `vscode`) pour rester testable hors VS Code.
 *
 * Chaque langage a sa convention d'import ; le but n'est pas d'être exhaustif
 * mais de rapprocher le code des paquets déclarés dans les lockfiles, pour
 * que le triage d'atteignabilité fonctionne au-delà de JS/Python.
 */

const JS_FILES = /\.([jt]sx?|mjs|cjs|vue|svelte)$/i;
const PY_FILES = /\.py$/i;
const GO_FILES = /\.go$/i;
const RUST_FILES = /\.rs$/i;
const JAVA_FILES = /\.(java|kt)$/i;
const PHP_FILES = /\.php$/i;
const RUBY_FILES = /\.rb$/i;
const CSHARP_FILES = /\.cs$/i;

/** import x from 'spec' | require('spec') | import('spec') | export … from 'spec' */
const JS_SPECIFIER = /(?:\bfrom|\bimport|\brequire)\s*\(?\s*['"]([^'"\n]+)['"]/g;

/** from a.b import c | import a.b, c */
const PY_FROM = /^\s*from\s+([\w.]+)\s+import\b/gm;
const PY_IMPORT = /^\s*import\s+([\w.,\s]+)$/gm;

/** import "mod" | import ( "mod" … ) — le nom OSV Go est le chemin complet du module. */
const GO_IMPORT_SINGLE = /^\s*import\s+"([^"]+)"/gm;
const GO_IMPORT_BLOCK = /\bimport\s*\(([^)]+)\)/gs;
const GO_QUOTED = /"([^"]+)"/g;

/** use serde_json::Value | extern crate serde_json — crate.io remplace '_' par '-'. */
const RUST_USE = /^\s*use\s+(\w+)\s*::/gm;
const RUST_EXTERN = /^\s*extern\s+crate\s+(\w+)/gm;

/** import org.apache.logging.log4j.Logger — le groupe Maven se déduit du préfixe. */
const JAVA_IMPORT = /^\s*import\s+(?:static\s+)?([\w.]+)\s*;?/gm;

/** use Vendor\Package\Class — le nom Packagist est 'vendor/package' en minuscules. */
const PHP_USE = /^\s*use\s+([A-Za-z][\w]*\\[A-Za-z][\w\\]*)\s*(?:as\s+\w+\s*)?;/gm;

/** require 'rails' | require "net/http" — le gem est le premier segment. */
const RUBY_REQUIRE = /^\s*require(?:_relative)?\s+['"]([^'"]+)['"]/gm;

/** using Newtonsoft.Json — l'identifiant NuGet est souvent le premier segment. */
const CSHARP_USING = /^\s*using\s+(?!static\b)([\w.]+)\s*;/gm;

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

/** Modules de la bibliothèque standard — jamais des paquets tiers. */
const STDLIB = new Set([
  // Go (préfixes les plus courants)
  'fmt', 'os', 'io', 'net', 'strings', 'strconv', 'time', 'context', 'sync',
  'errors', 'log', 'math', 'sort', 'bytes', 'bufio', 'path', 'regexp',
  'encoding', 'crypto', 'database', 'html', 'text', 'testing', 'flag',
  // Rust
  'std', 'core', 'alloc', 'crate', 'self', 'super',
  // Java / Kotlin
  'java', 'javax', 'kotlin', 'kotlinx',
  // C#
  'System', 'Microsoft',
]);

/** Relève les modules importés par un fichier source (tous langages supportés). */
export function extractImports(fsPath: string, text: string): FileImports {
  const specifiers = new Set<string>();
  const packages = new Set<string>();

  /** Spécificateur JS-like : le paquet se déduit du chemin. */
  const add = (spec: string): void => {
    const trimmed = spec.trim();
    if (!trimmed) return;
    specifiers.add(trimmed);
    const pkg = packageOfSpecifier(trimmed);
    if (pkg) packages.add(pkg);
  };

  /** Spécificateur + paquet explicitement différent (Go, Java, PHP, C#…). */
  const addWithPackage = (spec: string, pkg: string | null): void => {
    const trimmed = spec.trim();
    if (!trimmed) return;
    specifiers.add(trimmed);
    const root = pkg?.split('.')[0] ?? pkg;
    if (pkg && root && !STDLIB.has(root)) packages.add(pkg);
  };

  if (JS_FILES.test(fsPath)) {
    for (const m of text.matchAll(JS_SPECIFIER)) add(m[1]);
  }

  if (PY_FILES.test(fsPath)) {
    for (const m of text.matchAll(PY_FROM)) addWithPackage(m[1], m[1].split('.')[0]);
    for (const m of text.matchAll(PY_IMPORT)) {
      for (const mod of m[1].split(',')) {
        // "import numpy as np" → numpy
        const name = mod.trim().split(/\s+/)[0];
        addWithPackage(name, name.split('.')[0]);
      }
    }
  }

  if (GO_FILES.test(fsPath)) {
    for (const m of text.matchAll(GO_IMPORT_SINGLE)) {
      addWithPackage(m[1], m[1]); // chemin complet = nom OSV Go
    }
    for (const block of text.matchAll(GO_IMPORT_BLOCK)) {
      for (const q of block[1].matchAll(GO_QUOTED)) {
        addWithPackage(q[1], q[1]);
      }
    }
  }

  if (RUST_FILES.test(fsPath)) {
    const addCrate = (crate: string): void => {
      addWithPackage(crate, crate);
      // crates.io publie 'tokio-util', le code importe 'tokio_util'.
      if (crate.includes('_')) addWithPackage(crate, crate.replace(/_/g, '-'));
    };
    for (const m of text.matchAll(RUST_USE)) addCrate(m[1]);
    for (const m of text.matchAll(RUST_EXTERN)) addCrate(m[1]);
  }

  if (JAVA_FILES.test(fsPath)) {
    for (const m of text.matchAll(JAVA_IMPORT)) {
      const segments = m[1].split('.');
      // Le dernier segment est la classe ; le groupe Maven est le préfixe
      // (org.apache.logging.log4j.Logger → org.apache.logging.log4j). Le
      // triage accepte les correspondances par préfixe, un excès ne coûte rien.
      if (segments.length < 2) continue;
      const pkg = segments.slice(0, segments.length - 1).join('.');
      addWithPackage(m[1], pkg);
    }
  }

  if (PHP_FILES.test(fsPath)) {
    for (const m of text.matchAll(PHP_USE)) {
      const segments = m[1].split('\\');
      if (segments.length < 2) continue;
      const pkg = `${segments[0]}/${segments[1]}`.toLowerCase();
      addWithPackage(m[1].replace(/\\/g, '/'), pkg);
    }
  }

  if (RUBY_FILES.test(fsPath)) {
    for (const m of text.matchAll(RUBY_REQUIRE)) {
      if (m[1].startsWith('.')) continue;
      addWithPackage(m[1], m[1].split('/')[0]);
    }
  }

  if (CSHARP_FILES.test(fsPath)) {
    for (const m of text.matchAll(CSHARP_USING)) {
      addWithPackage(m[1], m[1].split('.')[0]);
    }
  }

  return { specifiers, packages };
}
