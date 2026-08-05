import { Finding, Severity } from './types';

interface SecretRule {
  name: string;
  regex: RegExp;
  severity: Severity;
  hint: string;
  /** Règle heuristique : on filtre les placeholders évidents (example, changeme…). */
  heuristic?: boolean;
}

const RULES: SecretRule[] = [
  { name: 'AWS Access Key', regex: /AKIA[0-9A-Z]{16}/g, severity: 'critical', hint: 'Révoquez la clé IAM immédiatement et utilisez des variables d\'environnement.' },
  { name: 'AWS Secret Key', regex: /aws.{0,20}?['"][0-9a-zA-Z\/+]{40}['"]/gi, severity: 'critical', hint: 'Révoquez la clé et utilisez AWS Secrets Manager.' },
  { name: 'GitHub Token', regex: /(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}/g, severity: 'critical', hint: 'Révoquez le token sur github.com/settings/tokens.' },
  { name: 'Anthropic API Key', regex: /sk-ant-[A-Za-z0-9_-]{20,}/g, severity: 'critical', hint: 'Révoquez la clé sur console.anthropic.com.' },
  { name: 'OpenAI API Key', regex: /sk-(?!ant-)[A-Za-z0-9_-]{20,}/g, severity: 'critical', hint: 'Révoquez la clé sur platform.openai.com.' },
  { name: 'Slack Token', regex: /xox[baprs]-[A-Za-z0-9-]{10,}/g, severity: 'high', hint: 'Révoquez le token dans l\'admin Slack.' },
  { name: 'Stripe Key', regex: /(sk|pk|rk)_(live|test)_[A-Za-z0-9]{16,}/g, severity: 'critical', hint: 'Régénérez la clé dans le dashboard Stripe.' },
  { name: 'Google API Key', regex: /AIza[0-9A-Za-z_-]{35}/g, severity: 'high', hint: 'Restreignez la clé dans Google Cloud Console.' },
  { name: 'Private Key', regex: /-----BEGIN (RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----/g, severity: 'critical', hint: 'Ne commitez jamais de clé privée. Régénérez-la.' },
  { name: 'JWT', regex: /eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g, severity: 'medium', hint: 'Les JWT peuvent contenir des données sensibles.' },
  { name: 'npm Token', regex: /npm_[A-Za-z0-9]{36}/g, severity: 'high', hint: 'Révoquez le token sur npmjs.com.' },
  { name: 'PyPI Token', regex: /pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{20,}/g, severity: 'high', hint: 'Révoquez le token sur pypi.org.' },
  { name: 'Connection String', regex: /(mongodb(\+srv)?|postgres(ql)?|mysql|redis|amqp):\/\/[^\s'"@\/]+:[^\s'"@\/]+@/gi, severity: 'high', hint: 'Identifiants dans l\'URL — utilisez des variables d\'environnement.' },
  { name: 'Mot de passe en dur', regex: /(password|passwd|pwd)\s*[:=]\s*['"][^'"\s]{8,}['"]/gi, severity: 'high', hint: 'Ne stockez jamais de mot de passe dans le code.', heuristic: true },
  { name: 'Clé API générique', regex: /(api[_-]?key|api[_-]?secret|access[_-]?token)\s*[:=]\s*['"][A-Za-z0-9_\-]{20,}['"]/gi, severity: 'high', hint: 'Déplacez ce secret dans un .env (et ajoutez .env au .gitignore).', heuristic: true },
];

/** Extensions dans lesquelles il vaut la peine de chercher des secrets. */
export const SECRET_FILE_TYPES =
  /\.(js|ts|jsx|tsx|mjs|cjs|py|rb|go|rs|java|php|cs|json|ya?ml|toml|env|ini|cfg|conf|sh|bash|zsh|ps1|txt|md|xml|html?)$|(^|[\\/])\.env(\.|$)/i;

const PLACEHOLDER = /(example|placeholder|your[_-]?|xxx+|changeme|dummy|test[_-]?key|<[^>]+>|\$\{)/i;

/** Au-delà, la ligne est probablement minifiée : on l'ignore (bruit + coût regex). */
const MAX_LINE_LENGTH = 2000;

function redact(match: string): string {
  if (match.length <= 8) return '***';
  return `${match.slice(0, 4)}${'*'.repeat(Math.min(match.length - 8, 20))}${match.slice(-4)}`;
}

/**
 * Cherche les secrets dans le contenu d'un fichier déjà lu.
 *
 * Les regex portent le flag /g : on passe par String.matchAll, qui travaille sur
 * un clone de la regex. Un `exec()` direct partagerait `lastIndex` d'une ligne à
 * l'autre et ferait rater des secrets.
 */
export function scanSecretsInText(text: string, relPath: string): Finding[] {
  const findings: Finding[] = [];
  const lines = text.split(/\r?\n/);

  lines.forEach((line, i) => {
    if (line.length > MAX_LINE_LENGTH) return;
    const isPlaceholder = PLACEHOLDER.test(line);

    for (const rule of RULES) {
      if (rule.heuristic && isPlaceholder) continue;
      for (const m of line.matchAll(rule.regex)) {
        findings.push({
          kind: 'secret',
          severity: rule.severity,
          id: rule.name,
          title: `${rule.name} détecté : ${redact(m[0])}`,
          description: rule.hint,
          file: relPath,
          line: i + 1,
        });
      }
    }
  });

  return findings;
}
