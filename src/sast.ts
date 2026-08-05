import { Finding, Severity } from './types';

interface SastRule {
  id: string;
  name: string;
  regex: RegExp;
  severity: Severity;
  description: string;
  /** Extensions ciblées par la règle. */
  languages: RegExp;
}

const JS = /\.([jt]sx?|mjs|cjs|vue|svelte)$/i;
const PY = /\.py$/i;

const RULES: SastRule[] = [
  // --- JavaScript / TypeScript ---
  { id: 'NDK-JS-001', name: 'eval()', regex: /\beval\s*\(/, severity: 'high', description: 'eval() exécute du code arbitraire — injection possible. Utilisez JSON.parse ou une alternative sûre.', languages: JS },
  { id: 'NDK-JS-002', name: 'Function() dynamique', regex: /new\s+Function\s*\(/, severity: 'high', description: 'new Function() équivaut à eval(). Évitez la génération de code dynamique.', languages: JS },
  { id: 'NDK-JS-003', name: 'innerHTML', regex: /\.innerHTML\s*=/, severity: 'medium', description: 'Affectation à innerHTML — risque XSS si la donnée vient de l\'utilisateur. Préférez textContent.', languages: JS },
  { id: 'NDK-JS-004', name: 'dangerouslySetInnerHTML', regex: /dangerouslySetInnerHTML/, severity: 'medium', description: 'Injection HTML brute dans React — risque XSS. Sanitizez avec DOMPurify.', languages: JS },
  { id: 'NDK-JS-005', name: 'child_process exec', regex: /\bexec\s*\(\s*[`'"]/, severity: 'high', description: 'exec() avec chaîne — injection de commandes si la donnée est externe. Préférez execFile/spawn avec tableau d\'arguments.', languages: JS },
  { id: 'NDK-JS-006', name: 'SQL concaténé', regex: /(SELECT|INSERT|UPDATE|DELETE|DROP)\s+[^`'"]*['"`]\s*\+/i, severity: 'high', description: 'Requête SQL construite par concaténation — injection SQL. Utilisez des requêtes paramétrées.', languages: JS },
  { id: 'NDK-JS-007', name: 'Crypto faible (MD5/SHA1)', regex: /createHash\s*\(\s*['"](md5|sha1)['"]/, severity: 'medium', description: 'MD5/SHA1 sont cassés. Utilisez SHA-256+ (ou bcrypt/argon2 pour les mots de passe).', languages: JS },
  { id: 'NDK-JS-008', name: 'CORS permissif', regex: /Access-Control-Allow-Origin['"]?\s*[:,]\s*['"]\*['"]/, severity: 'medium', description: 'CORS ouvert à * — n\'importe quel site peut appeler votre API.', languages: JS },
  { id: 'NDK-JS-009', name: 'TLS désactivé', regex: /rejectUnauthorized\s*:\s*false/, severity: 'critical', description: 'Vérification TLS désactivée — vulnérable aux attaques MITM.', languages: JS },

  // --- Python ---
  { id: 'NDK-PY-001', name: 'eval() / exec()', regex: /(?<![\w.])(eval|exec)\s*\(/, severity: 'high', description: 'eval()/exec() exécutent du code arbitraire. Utilisez ast.literal_eval pour la donnée.', languages: PY },
  { id: 'NDK-PY-002', name: 'os.system()', regex: /os\.system\s*\(/, severity: 'high', description: 'os.system() — injection de commandes. Préférez subprocess avec liste d\'arguments et shell=False.', languages: PY },
  { id: 'NDK-PY-003', name: 'subprocess shell=True', regex: /subprocess\.\w+\([^)]*shell\s*=\s*True/, severity: 'high', description: 'shell=True expose à l\'injection de commandes si la donnée est externe.', languages: PY },
  { id: 'NDK-PY-004', name: 'pickle.loads', regex: /pickle\.loads?\s*\(/, severity: 'high', description: 'pickle peut exécuter du code à la désérialisation. Ne chargez jamais de pickle non fiable.', languages: PY },
  { id: 'NDK-PY-005', name: 'yaml.load non sûr', regex: /yaml\.load\s*\((?![^)]*SafeLoader)/, severity: 'high', description: 'yaml.load sans SafeLoader — exécution de code possible. Utilisez yaml.safe_load.', languages: PY },
  { id: 'NDK-PY-006', name: 'SQL concaténé (f-string)', regex: /(SELECT|INSERT|UPDATE|DELETE)\s+[^'"]*f['"]/i, severity: 'high', description: 'Requête SQL en f-string — injection SQL. Utilisez des paramètres (%s, ?).', languages: PY },
  { id: 'NDK-PY-007', name: 'TLS désactivé', regex: /verify\s*=\s*False/, severity: 'high', description: 'verify=False désactive la vérification TLS — attaque MITM possible.', languages: PY },
  { id: 'NDK-PY-008', name: 'Mot de passe hashé en MD5/SHA1', regex: /hashlib\.(md5|sha1)\s*\(/, severity: 'medium', description: 'MD5/SHA1 cassés. Utilisez hashlib.sha256 ou bcrypt/argon2.', languages: PY },

  // --- Générique ---
  { id: 'NDK-GEN-001', name: 'HTTP non chiffré', regex: /['"]http:\/\/(?!localhost|127\.0\.0\.1|0\.0\.0\.0|schemas?\.|www\.w3\.org|xmlns)/, severity: 'low', description: 'URL en http:// clair — préférez https://.', languages: /\.(js|ts|jsx|tsx|mjs|cjs|py|go|rs|java|php|rb|cs)$/i },
  { id: 'NDK-GEN-002', name: 'Debug activé', regex: /\b(debug|DEBUG)\s*[:=]\s*(true|True|1)\b/, severity: 'low', description: 'Mode debug activé — à désactiver en production (fuite d\'informations).', languages: /\.(js|ts|py|json|ya?ml|env|ini|cfg)$/i },
];

/** Extensions pour lesquelles au moins une règle SAST existe. */
export const SAST_FILE_TYPES = /\.([jt]sx?|mjs|cjs|vue|svelte|py|go|rs|java|php|rb|cs|json|ya?ml|env|ini|cfg)$/i;

/** Ligne de commentaire mono-ligne — évite de signaler du code commenté. */
const COMMENT = /^\s*(\/\/|#|\*|<!--)/;

/** Applique les règles SAST au contenu d'un fichier déjà lu. */
export function scanCodeInText(fsPath: string, relPath: string, text: string): Finding[] {
  const applicable = RULES.filter((r) => r.languages.test(fsPath));
  if (applicable.length === 0) return [];

  const findings: Finding[] = [];
  const lines = text.split(/\r?\n/);

  lines.forEach((line, i) => {
    if (COMMENT.test(line)) return;
    for (const rule of applicable) {
      if (rule.regex.test(line)) {
        findings.push({
          kind: 'sast',
          severity: rule.severity,
          id: rule.id,
          title: `${rule.name} (${rule.id})`,
          description: rule.description,
          file: relPath,
          line: i + 1,
        });
      }
    }
  });

  return findings;
}
