import * as vscode from 'vscode';

/**
 * Résout un chemin relatif de rapport en URI.
 * En multi-root, `asRelativePath` préfixe le chemin avec le nom du dossier :
 * on essaie donc chaque dossier, avec et sans ce préfixe.
 */
export async function resolveWorkspaceFile(file: string): Promise<vscode.Uri | undefined> {
  for (const folder of vscode.workspace.workspaceFolders ?? []) {
    const candidates = [file, file.replace(new RegExp(`^${folder.name}[\\\\/]`), '')];
    for (const candidate of candidates) {
      const uri = vscode.Uri.joinPath(folder.uri, candidate);
      try {
        await vscode.workspace.fs.stat(uri);
        return uri;
      } catch {
        // pas dans ce dossier — on continue
      }
    }
  }
  return undefined;
}
