import * as fs from 'fs';
import * as path from 'path';
import * as vscode from 'vscode';

/**
 * Charge morphicons (MIT) depuis node_modules et produit un script autonome,
 * inliné dans le webview (CSP default-src 'none' : aucun fichier externe).
 *
 * Le build ESM est découpé en deux fichiers : un chunk `spring-*.js` (nom
 * hashé) et `dom.js` qui l'importe. On fusionne les deux en un seul script
 * module qui expose `window.NDK_MORPH = { createMorph }`.
 *
 * En cas de problème (package absent, layout inattendu…), retourne '' :
 * le webview retombe alors sur des changements d'icônes sans animation.
 */
export function loadMorphiconsSource(context: vscode.ExtensionContext): string {
  try {
    const distDir = path.join(context.extensionPath, 'node_modules', 'morphicons', 'dist');
    let domSrc = fs.readFileSync(path.join(distDir, 'dom.js'), 'utf8');

    // Repère le chunk importé par dom.js ; repli : premier spring-*.js du dossier.
    const importRe = /^import\s*\{[^}]*\}\s*from\s*"\.\/(spring-[^"]+\.js)";?\s*$/m;
    const importMatch = domSrc.match(importRe);
    let chunkName = importMatch?.[1];
    if (!chunkName) {
      chunkName = fs.readdirSync(distDir).find((f) => /^spring-.*\.js$/.test(f));
    }
    if (!chunkName) return '';

    let chunkSrc = fs.readFileSync(path.join(distDir, chunkName), 'utf8');

    // Le chunk finit par `export { X as a, Y as b };` : on le réécrit en
    // `const a = X; const b = Y;`. Quand il n'y a pas d'alias (`export { X }`),
    // le nom existe déjà : on saute la déclaration pour éviter un doublon.
    const exportRe = /export\s*\{([^}]*)\};?\s*$/m;
    const exportMatch = chunkSrc.match(exportRe);
    if (exportMatch) {
      const decls = exportMatch[1]
        .split(',')
        .map((s) => s.trim())
        .filter(Boolean)
        .map((entry) => {
          const alias = entry.match(/^(\S+)\s+as\s+(\S+)$/);
          return alias ? `const ${alias[2]} = ${alias[1]};` : '';
        })
        .filter(Boolean)
        .join('\n');
      chunkSrc = chunkSrc.replace(exportRe, decls);
    }

    // dom.js : on supprime la ligne d'import du chunk et l'export ESM final.
    domSrc = domSrc
      .replace(importRe, '')
      .replace(/export\s*\{[^}]*\};?\s*$/m, '');

    return (
      chunkSrc +
      '\n' +
      domSrc +
      '\nwindow.NDK_MORPH = { createMorph: createMorph };\n'
    );
  } catch {
    // Jamais d'exception : l'animation des icônes est un bonus, pas un besoin.
    return '';
  }
}
