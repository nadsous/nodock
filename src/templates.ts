import { Finding, Severity } from './types';

/**
 * Moteur de templates de vulnérabilités en YAML.
 *
 * Un template décrit UNE règle : où elle s'applique (`files`), ce qu'elle
 * cherche (`matchers`, combinés en `or`/`and`) et ce qui la disculpe
 * (`exempt`). Les utilisateurs peuvent déposer leurs propres templates dans
 * `.nodock/templates/` — même format, aucune recompilation.
 *
 * Ce module est volontairement pur (aucun import `vscode`, aucune I/O) pour
 * rester testable par un simple `node --test`. Le YAML accepté est un
 * SOUS-ENSEMBLE volontairement réduit : mappings imbriqués, listes `- item`,
 * listes inline `[a, b]`, scalaires quotés ou nus, commentaires `#`.
 * Pas d'ancres, pas de blocs `|`/`>`, pas de multi-documents : un format
 * simple reste lisible, et un template trop exotique échoue avec un message
 * clair plutôt que de produire un comportement silencieusement faux.
 */

export interface TemplateMatcher {
  type: 'regex' | 'word';
  /** Motif regex (type regex), compilé à la validation. */
  regex?: RegExp;
  /** Motifs littéraux (type word). */
  words?: string[];
  /** Sensibilité à la casse (type word uniquement ; les regex portent leurs flags). */
  ignoreCase?: boolean;
}

export interface Template {
  id: string;
  name: string;
  severity: Severity;
  description: string;
  remediation?: string;
  reference?: string;
  tags: string[];
  /** Chemins ciblés (testé sur le chemin du fichier). */
  files: RegExp;
  matchers: TemplateMatcher[];
  condition: 'or' | 'and';
  /** Motif qui disculpe le match, évalué sur une fenêtre de quelques lignes. */
  exempt?: RegExp;
  /** true = les matchers regex sont appliqués au texte entier (pas ligne par ligne). */
  multiline: boolean;
  /** Origine du template (pour les messages de diagnostic). */
  source: string;
}

/** Lignes examinées de part et d'autre du match pour évaluer une exemption. */
const EXEMPT_WINDOW = 2;

/** Ligne de commentaire mono-ligne — évite de signaler du code commenté. */
const COMMENT = /^\s*(\/\/|#|\*|<!--)/;

const SEVERITIES: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];

// ---------------------------------------------------------------------------
// Sous-ensemble YAML
// ---------------------------------------------------------------------------

type YamlValue = string | boolean | number | YamlValue[] | { [key: string]: YamlValue };

interface YamlLine {
  indent: number;
  content: string;
}

/** Découpe le texte en lignes significatives (hors commentaires et lignes vides). */
function tokenize(text: string): YamlLine[] {
  const out: YamlLine[] = [];
  for (const raw of text.split(/\r?\n/)) {
    if (!raw.trim() || raw.trimStart().startsWith('#')) continue;
    if (/^\s*---\s*$/.test(raw)) continue; // séparateur de document, ignoré
    const indent = raw.length - raw.trimStart().length;
    out.push({ indent, content: raw.trim() });
  }
  return out;
}

/** Supprime un commentaire de fin de ligne (hors chaînes quotées). */
function stripComment(s: string): string {
  let quote: string | null = null;
  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    if (quote) {
      if (c === quote && s[i - 1] !== '\\') quote = null;
    } else if (c === '"' || c === "'") {
      quote = c;
    } else if (c === '#' && (i === 0 || s[i - 1] === ' ')) {
      return s.slice(0, i).trimEnd();
    }
  }
  return s;
}

/** Scalaire : chaîne quotée, liste inline [a, b], booléen, nombre ou chaîne nue. */
function parseScalar(raw: string): YamlValue {
  const s = stripComment(raw.trim());
  if (s.startsWith('[')) {
    if (!s.endsWith(']')) throw new Error(`liste inline non terminée : ${s}`);
    const inner = s.slice(1, -1).trim();
    if (!inner) return [];
    return splitInline(inner).map((item) => parseScalar(item));
  }
  if (s.startsWith("'")) {
    if (!s.endsWith("'") || s.length < 2) throw new Error(`chaîne non terminée : ${s}`);
    return s.slice(1, -1).replace(/''/g, "'");
  }
  if (s.startsWith('"')) {
    if (!s.endsWith('"') || s.length < 2) throw new Error(`chaîne non terminée : ${s}`);
    return s
      .slice(1, -1)
      .replace(/\\(["\\nrt])/g, (_, c: string) =>
        c === 'n' ? '\n' : c === 'r' ? '\r' : c === 't' ? '\t' : c
      );
  }
  if (s === 'true') return true;
  if (s === 'false') return false;
  if (/^-?\d+(\.\d+)?$/.test(s)) return Number(s);
  return s;
}

/** Sépare les éléments d'une liste inline en respectant les guillemets. */
function splitInline(inner: string): string[] {
  const items: string[] = [];
  let quote: string | null = null;
  let current = '';
  for (const c of inner) {
    if (quote) {
      current += c;
      if (c === quote) quote = null;
    } else if (c === '"' || c === "'") {
      quote = c;
      current += c;
    } else if (c === ',') {
      items.push(current.trim());
      current = '';
    } else {
      current += c;
    }
  }
  if (current.trim()) items.push(current.trim());
  return items;
}

/** Parse un bloc à l'indentation donnée. Retourne [valeur, index suivant]. */
function parseBlock(lines: YamlLine[], start: number, indent: number): [YamlValue, number] {
  const isList = lines[start].content.startsWith('- ') || lines[start].content === '-';
  if (isList) {
    const list: YamlValue[] = [];
    let i = start;
    while (i < lines.length && lines[i].indent === indent && lines[i].content.startsWith('-')) {
      const itemText = lines[i].content === '-' ? '' : lines[i].content.slice(2).trim();
      i++;
      if (!itemText) {
        // `-` seul : la valeur est le bloc indenté qui suit.
        if (i < lines.length && lines[i].indent > indent) {
          const [value, next] = parseBlock(lines, i, lines[i].indent);
          list.push(value);
          i = next;
        } else {
          list.push('');
        }
      } else if (/^[^:'"[\]]+\s*:(\s|$)/.test(itemText)) {
        // Item de liste qui ouvre un mapping (`- type: regex` suivi de clés indentées).
        const map: { [key: string]: YamlValue } = {};
        const colon = itemText.indexOf(':');
        const key = itemText.slice(0, colon).trim();
        const rest = itemText.slice(colon + 1).trim();
        if (rest) map[key] = parseScalar(rest);
        if (i < lines.length && lines[i].indent > indent) {
          const [value, next] = parseBlock(lines, i, lines[i].indent);
          if (typeof value === 'object' && !Array.isArray(value)) {
            Object.assign(map, value);
          }
          i = next;
        }
        list.push(map);
      } else {
        list.push(parseScalar(itemText));
      }
    }
    return [list, i];
  }

  const map: { [key: string]: YamlValue } = {};
  let i = start;
  while (i < lines.length && lines[i].indent === indent && !lines[i].content.startsWith('-')) {
    const colon = lines[i].content.indexOf(':');
    if (colon === -1) throw new Error(`ligne YAML invalide : ${lines[i].content}`);
    const key = lines[i].content.slice(0, colon).trim();
    const rest = stripComment(lines[i].content.slice(colon + 1).trim());
    i++;
    if (rest) {
      map[key] = parseScalar(rest);
    } else if (i < lines.length && lines[i].indent > indent) {
      const [value, next] = parseBlock(lines, i, lines[i].indent);
      map[key] = value;
      i = next;
    } else {
      map[key] = '';
    }
  }
  return [map, i];
}

/** Parse le sous-ensemble YAML accepté par les templates Nodock. */
export function parseYaml(text: string): { [key: string]: YamlValue } {
  const lines = tokenize(text);
  if (lines.length === 0) throw new Error('template vide');
  const [value] = parseBlock(lines, 0, lines[0].indent);
  if (typeof value !== 'object' || Array.isArray(value)) {
    throw new Error('un template doit être un mapping YAML (clé: valeur)');
  }
  return value;
}

// ---------------------------------------------------------------------------
// Validation d'un template
// ---------------------------------------------------------------------------

function asString(value: YamlValue | undefined, field: string, id: string): string {
  if (typeof value !== 'string' || !value.trim()) {
    throw new Error(`${id} : champ '${field}' manquant ou invalide`);
  }
  return value.trim();
}

function asStringList(value: YamlValue | undefined): string[] {
  if (Array.isArray(value)) return value.map(String).filter(Boolean);
  if (typeof value === 'string' && value.trim()) {
    // `tags: go, injection` — liste en une seule chaîne.
    return value.split(',').map((t) => t.trim()).filter(Boolean);
  }
  return [];
}

/** Un élément de `files` : extension nue ('go') ou regex ('\\.(go|mod)$'). */
function filePatternToRegex(value: YamlValue | undefined, id: string): RegExp {
  const items = asStringList(value);
  if (items.length === 0) throw new Error(`${id} : champ 'files' manquant (regex ou extensions)`);
  const parts = items.map((item) =>
    /^[\w]+$/.test(item) ? `\\.${item}$` : `(?:${item})`
  );
  try {
    return new RegExp(parts.join('|'), 'i');
  } catch (e) {
    throw new Error(`${id} : 'files' n'est pas une regex valide (${(e as Error).message})`);
  }
}

function parseMatcher(raw: YamlValue, id: string, multiline: boolean): TemplateMatcher {
  if (typeof raw !== 'object' || Array.isArray(raw)) {
    throw new Error(`${id} : chaque matcher doit être un mapping (type, pattern/words)`);
  }
  const type = (raw as Record<string, YamlValue>).type;
  if (type !== 'regex' && type !== 'word') {
    throw new Error(`${id} : matcher.type doit être 'regex' ou 'word'`);
  }
  if (type === 'regex') {
    const pattern = asString((raw as Record<string, YamlValue>).pattern, 'matchers.pattern', id);
    const flags = String((raw as Record<string, YamlValue>).flags ?? '');
    if (!/^[ims]*$/.test(flags)) throw new Error(`${id} : flags regex invalides '${flags}'`);
    try {
      // Multiline : on matche le texte entier, il faut le flag g pour matchAll.
      return { type, regex: new RegExp(pattern, multiline ? `${flags}gm` : flags) };
    } catch (e) {
      throw new Error(`${id} : regex invalide '${pattern}' (${(e as Error).message})`);
    }
  }
  const words = asStringList((raw as Record<string, YamlValue>).words);
  if (words.length === 0) throw new Error(`${id} : matcher word sans 'words'`);
  return { type, words, ignoreCase: (raw as Record<string, YamlValue>).ignoreCase === true };
}

/**
 * Valide et compile un template YAML. Lève une Error explicite si le template
 * est invalide — le chargeur la transforme en note non bloquante du rapport.
 */
export function parseTemplate(text: string, source: string): Template {
  const doc = parseYaml(text);
  const id = asString(doc.id, 'id', source);
  const info = doc.info;
  if (typeof info !== 'object' || Array.isArray(info)) {
    throw new Error(`${id} : section 'info' manquante`);
  }
  const infoMap = info as Record<string, YamlValue>;
  const severity = String(infoMap.severity ?? '').toLowerCase() as Severity;
  if (!SEVERITIES.includes(severity)) {
    throw new Error(`${id} : info.severity doit être l'une de ${SEVERITIES.join(', ')}`);
  }
  const rawMatchers = doc.matchers;
  if (!Array.isArray(rawMatchers) || rawMatchers.length === 0) {
    throw new Error(`${id} : au moins un matcher est requis`);
  }
  const condition = String(doc.condition ?? 'or').toLowerCase();
  if (condition !== 'or' && condition !== 'and') {
    throw new Error(`${id} : condition doit être 'or' ou 'and'`);
  }
  const multiline = doc.multiline === true;
  const template: Template = {
    id,
    name: asString(infoMap.name, 'info.name', id),
    severity,
    description: asString(infoMap.description, 'info.description', id),
    remediation:
      typeof infoMap.remediation === 'string' ? infoMap.remediation.trim() : undefined,
    reference: typeof infoMap.reference === 'string' ? infoMap.reference.trim() : undefined,
    tags: asStringList(infoMap.tags),
    files: filePatternToRegex(doc.files, id),
    matchers: [],
    condition,
    multiline,
    source,
  };
  template.matchers = rawMatchers.map((m) => parseMatcher(m, id, multiline));
  if (typeof doc.exempt === 'string' && doc.exempt.trim()) {
    try {
      template.exempt = new RegExp(doc.exempt.trim());
    } catch (e) {
      throw new Error(`${id} : 'exempt' n'est pas une regex valide (${(e as Error).message})`);
    }
  }
  return template;
}

// ---------------------------------------------------------------------------
// Application des templates
// ---------------------------------------------------------------------------

/** true si le fragment de texte satisfait les matchers du template. */
function matchesAll(template: Template, fragment: string): boolean {
  const test = (m: TemplateMatcher): boolean => {
    if (m.type === 'regex') return m.regex!.test(fragment);
    const haystack = m.ignoreCase ? fragment.toLowerCase() : fragment;
    return m.words!.some((w) => haystack.includes(m.ignoreCase ? w.toLowerCase() : w));
  };
  return template.condition === 'and'
    ? template.matchers.every(test)
    : template.matchers.some(test);
}

function toFinding(template: Template, relPath: string, line: number): Finding {
  let description = template.description;
  if (template.remediation) description += `\n\n🛡️ ${template.remediation}`;
  return {
    kind: 'sast',
    severity: template.severity,
    id: template.id,
    title: `${template.name} (${template.id})`,
    description,
    file: relPath,
    line,
    url: template.reference,
  };
}

/** Union des chemins ciblés par un ensemble de templates (filtre de pré-sélection). */
export function templateFileTypes(templates: Template[]): RegExp | null {
  if (templates.length === 0) return null;
  const sources = templates.map((t) => `(?:${t.files.source})`);
  return new RegExp(sources.join('|'), 'i');
}

/**
 * Applique des templates au contenu d'un fichier déjà lu.
 * Mêmes garde-fous que le SAST natif : lignes de commentaire ignorées,
 * exemptions évaluées sur une fenêtre, plafond anti-bruit géré par l'appelant.
 */
export function scanTemplatesInText(
  fsPath: string,
  relPath: string,
  text: string,
  templates: Template[]
): Finding[] {
  const applicable = templates.filter((t) => t.files.test(fsPath));
  if (applicable.length === 0) return [];

  const findings: Finding[] = [];
  const lines = text.split(/\r?\n/);

  // --- Templates ligne par ligne ---
  const lineTemplates = applicable.filter((t) => !t.multiline);
  if (lineTemplates.length > 0) {
    lines.forEach((line, i) => {
      if (COMMENT.test(line)) return;
      for (const template of lineTemplates) {
        if (!matchesAll(template, line)) continue;
        if (template.exempt) {
          const window = lines
            .slice(Math.max(0, i - EXEMPT_WINDOW), i + EXEMPT_WINDOW + 1)
            .join('\n');
          if (template.exempt.test(window)) continue;
        }
        findings.push(toFinding(template, relPath, i + 1));
      }
    });
  }

  // --- Templates multi-lignes : matchAll sur le texte entier ---
  for (const template of applicable.filter((t) => t.multiline)) {
    // En multi-lignes, chaque matcher regex est évalué sur tout le texte ; les
    // occurrences remontées sont celles du PREMIER matcher qui matche.
    const fragments: Array<{ index: number; length: number }> = [];
    for (const matcher of template.matchers) {
      if (matcher.type !== 'regex') continue;
      for (const m of text.matchAll(matcher.regex!)) {
        fragments.push({ index: m.index ?? 0, length: m[0].length });
      }
      if (fragments.length > 0) break; // condition or : le premier matcher suffit
    }
    if (fragments.length === 0) continue;
    if (template.condition === 'and' && !matchesAll(template, text)) continue;
    for (const f of fragments) {
      const fragment = text.slice(f.index, f.index + f.length);
      if (template.exempt?.test(fragment)) continue;
      const line = text.slice(0, f.index).split('\n').length;
      findings.push(toFinding(template, relPath, line));
    }
  }

  return findings;
}
