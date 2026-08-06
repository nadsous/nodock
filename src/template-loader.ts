import * as vscode from 'vscode';
import { parseTemplate, Template } from './templates';

/**
 * Chargement des templates YAML (côté VS Code : I/O et emplacements).
 * La logique de parsing et d'application reste dans `templates.ts` (pur).
 */

export interface TemplatesLoadResult {
  templates: Template[];
  /** Templates invalides ou dossiers inaccessibles — jamais bloquant. */
  notes: string[];
}

/** Lit tous les templates d'un dossier. Erreurs → notes, jamais d'exception. */
async function loadFromDir(
  dir: vscode.Uri,
  origin: string,
  notes: string[]
): Promise<Template[]> {
  const out: Template[] = [];
  let entries: Array<[string, vscode.FileType]>;
  try {
    entries = await vscode.workspace.fs.readDirectory(dir);
  } catch {
    return out; // dossier absent : normal pour `.nodock/templates`
  }
  for (const [name, type] of entries) {
    if (type !== vscode.FileType.File || !/\.ya?ml$/i.test(name)) continue;
    const file = vscode.Uri.joinPath(dir, name);
    try {
      const text = Buffer.from(await vscode.workspace.fs.readFile(file)).toString('utf8');
      out.push(parseTemplate(text, `${origin}/${name}`));
    } catch (e) {
      notes.push(`Template '${origin}/${name}' ignoré : ${(e as Error).message}`);
    }
  }
  return out;
}

/**
 * Charge les templates par ordre de priorité : embarqués d'abord, puis ceux du
 * projet (`.nodock/templates/`) et des chemins additionnels, qui peuvent
 * REMPLACER un template embarqué en réutilisant son `id`.
 */
export async function loadTemplates(
  context: vscode.ExtensionContext,
  extraPaths: string[]
): Promise<TemplatesLoadResult> {
  const notes: string[] = [];
  const byId = new Map<string, Template>();

  const addAll = (templates: Template[]): void => {
    for (const t of templates) byId.set(t.id, t);
  };

  // 1. Templates embarqués (dossier `templates/` packagé avec l'extension).
  addAll(await loadFromDir(vscode.Uri.joinPath(context.extensionUri, 'templates'), 'embarqué', notes));

  // 2. Templates du projet scanné.
  const root = vscode.workspace.workspaceFolders?.[0]?.uri;
  if (root) {
    addAll(await loadFromDir(vscode.Uri.joinPath(root, '.nodock', 'templates'), '.nodock/templates', notes));
  }

  // 3. Chemins additionnels (réglage nodock.templatePaths, relatifs au workspace).
  for (const p of extraPaths) {
    if (!p.trim()) continue;
    const dir = /^([a-zA-Z]:[\\/]|[\\/])/.test(p)
      ? vscode.Uri.file(p)
      : root
        ? vscode.Uri.joinPath(root, p)
        : undefined;
    if (!dir) continue;
    addAll(await loadFromDir(dir, p, notes));
  }

  return { templates: [...byId.values()], notes };
}
