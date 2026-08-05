/**
 * Produit le README destiné au paquet VSIX à partir du README du dépôt.
 *
 * Le marketplace VS Code refuse les images SVG ; GitHub, lui, les affiche très
 * bien. Plutôt que de renoncer au logo ou de maintenir deux fichiers en
 * parallèle, on dérive le second du premier à chaque publication.
 */
const fs = require('fs');
const path = require('path');

const ROOT = path.join(__dirname, '..');
const SOURCE = path.join(ROOT, 'README.md');
const TARGET = path.join(ROOT, 'README.vsix.md');

const readme = fs.readFileSync(SOURCE, 'utf8');

const stripped = readme
  // Balises <img> pointant vers un SVG local.
  .replace(/^\s*<img\s+src="[^"]*\.svg"[^>]*>\s*$/gim, '')
  // Équivalent en syntaxe Markdown.
  .replace(/^\s*!\[[^\]]*\]\([^)]*\.svg\)\s*$/gim, '')
  // Le <p align="center"> devenu vide une fois l'image retirée.
  .replace(/<p align="center">\s*<\/p>\s*/g, '');

fs.writeFileSync(TARGET, stripped, 'utf8');
console.log(`README.vsix.md généré (${stripped.length} caractères, SVG retirés).`);
