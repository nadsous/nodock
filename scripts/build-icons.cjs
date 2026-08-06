/**
 * Extrait, À LA COMPILATION, les chemins SVG des icônes Lucide utilisées par le
 * panneau, et les écrit dans `src/icons-data.ts`.
 *
 * Pourquoi ne pas lire node_modules au démarrage de l'extension : lucide pèse
 * 27 Mo pour 3548 fichiers, et le panneau en utilise 22. Les embarquer tous
 * faisait passer le paquet de 92 Ko à 4,4 Mo — pour un scanner de sécurité,
 * c'est autant de surface d'approvisionnement livrée pour rien.
 *
 * Résultat : lucide devient une dépendance de développement, le fichier généré
 * est versionné, et construire l'extension n'exige plus lucide du tout.
 *
 *   node scripts/build-icons.cjs
 */
const fs = require('fs');
const path = require('path');

const ROOT = path.join(__dirname, '..');
const ICONS_DIR = path.join(ROOT, 'node_modules', 'lucide', 'dist', 'esm', 'icons');
const TARGET = path.join(ROOT, 'src', 'icons-data.ts');

/** Icônes utilisées par le panneau (groupes, onglets, boutons, sévérités). */
const ICON_NAMES = [
  'shield', 'shield-alert', 'shield-check', 'bug', 'crosshair', 'lock-keyhole',
  'file-code-2', 'globe', 'scale', 'list-checks', 'package', 'newspaper',
  'refresh-cw', 'download', 'triangle-alert', 'info', 'check', 'chevron-right',
  'x', 'zap', 'terminal', 'file-warning', 'radar',
];

/** Renommages lucide 1.29 : le webview garde les noms historiques. */
const RENAMED = {
  'file-code-2': 'file-code-corner',
  'file-warning': 'file-exclamation-point',
};

/** Convertit un élément Lucide (tag + attributs) en commandes de path `d`. */
function elementToD(tag, attrs) {
  switch (tag) {
    case 'path':
      return attrs.d ?? '';
    case 'line':
      return `M${attrs.x1} ${attrs.y1}L${attrs.x2} ${attrs.y2}`;
    case 'circle': {
      const cx = Number(attrs.cx);
      const cy = Number(attrs.cy);
      const r = Number(attrs.r);
      return `M${cx - r} ${cy}a${r} ${r} 0 1 0 ${2 * r} 0a${r} ${r} 0 1 0 ${-2 * r} 0`;
    }
    case 'rect': {
      const x = Number(attrs.x);
      const y = Number(attrs.y);
      const w = Number(attrs.width);
      const h = Number(attrs.height);
      const rx = Math.min(Number(attrs.rx ?? 0), w / 2, h / 2);
      if (rx > 0) {
        return (
          `M${x + rx} ${y}h${w - 2 * rx}a${rx} ${rx} 0 0 1 ${rx} ${rx}` +
          `v${h - 2 * rx}a${rx} ${rx} 0 0 1 ${-rx} ${rx}h${-(w - 2 * rx)}` +
          `a${rx} ${rx} 0 0 1 ${-rx} ${-rx}v${-(h - 2 * rx)}a${rx} ${rx} 0 0 1 ${rx} ${-rx}z`
        );
      }
      return `M${x} ${y}h${w}v${h}h${-w}z`;
    }
    case 'polyline':
    case 'polygon': {
      const pts = String(attrs.points ?? '')
        .trim()
        .split(/\s+/)
        .map((p) => p.split(',').map(Number))
        .filter((p) => p.length === 2 && p.every((n) => Number.isFinite(n)));
      if (!pts.length) return '';
      const [first, ...rest] = pts;
      return (
        `M${first[0]} ${first[1]}` +
        rest.map((p) => `L${p[0]} ${p[1]}`).join('') +
        (tag === 'polygon' ? 'z' : '')
      );
    }
    default:
      return '';
  }
}

function extract() {
  const out = {};
  const missing = [];

  for (const name of ICON_NAMES) {
    const file = path.join(ICONS_DIR, `${RENAMED[name] ?? name}.mjs`);
    try {
      const text = fs.readFileSync(file, 'utf8');
      const match = text.match(/const \w+ = (\[[\s\S]*?\]);/);
      if (!match) {
        missing.push(name);
        continue;
      }
      // Attributs à clés nues ({ d: "…" }) : on les quote pour obtenir du JSON.
      const json = match[1].replace(/([{,]\s*)([A-Za-z_]\w*)\s*:/g, '$1"$2":');
      const d = JSON.parse(json)
        .map(([tag, attrs]) => elementToD(tag, attrs))
        .filter(Boolean)
        .join(' ');
      if (d) out[name] = d;
      else missing.push(name);
    } catch {
      missing.push(name);
    }
  }

  return { out, missing };
}

if (!fs.existsSync(ICONS_DIR)) {
  // Le fichier généré est versionné : sans lucide installé, on garde l'existant.
  console.log('lucide absent — src/icons-data.ts conservé tel quel.');
  process.exit(0);
}

const { out, missing } = extract();
const body = Object.entries(out)
  .map(([name, d]) => `  ${JSON.stringify(name)}: ${JSON.stringify(d)},`)
  .join('\n');

fs.writeFileSync(
  TARGET,
  `/**\n` +
    ` * GÉNÉRÉ par scripts/build-icons.cjs — ne pas modifier à la main.\n` +
    ` *\n` +
    ` * Chemins SVG des icônes Lucide (licence ISC) utilisées par le panneau.\n` +
    ` * Extraits à la compilation pour que lucide reste une dépendance de\n` +
    ` * développement et n'entre pas dans le paquet publié.\n` +
    ` */\n\n` +
    `export const ICON_PATHS: Record<string, string> = {\n${body}\n};\n`,
  'utf8'
);

console.log(
  `src/icons-data.ts généré : ${Object.keys(out).length}/${ICON_NAMES.length} icônes` +
    (missing.length ? ` (absentes : ${missing.join(', ')})` : '')
);
