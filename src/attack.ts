import { Finding, Severity } from './types';

/**
 * Module « Vecteurs d'attaque » — raisonne comme un hacker qui veut compromettre
 * LE PROJET : scripts d'installation malveillants, commandes dangereuses
 * copiées-collées, dependency confusion, secrets commités dans la config des
 * outils. Chaque règle documente le scénario d'attaque ET la prévention.
 *
 * Ce qui est couvert ailleurs volontairement absent ici :
 *  - Dockerfile / docker-compose / GitHub Actions → infra.ts
 *  - vulnérabilités applicatives (SSRF, injections…) → websec.ts / sast.ts
 */

interface AttackRule {
  id: string;
  name: string;
  regex: RegExp;
  severity: Severity;
  /** Comment le hacker exploite ce pattern. */
  attack: string;
  /** Comment s'en protéger. */
  prevention: string;
  /** true = pertinente aussi dans la documentation (instructions dangereuses). */
  inDocs?: boolean;
  /**
   * Motif systémique : un seul finding groupé pour tout le projet.
   * Les scripts d'installation d'outils tiers embarqués répètent le même
   * `curl | bash` dans chaque dossier — c'est une seule décision à prendre,
   * pas vingt-trois problèmes distincts.
   */
  aggregate?: boolean;
}

interface FileRuleSet {
  match: RegExp;
  rules: AttackRule[];
}

/** Au-delà, la ligne est probablement minifiée : bruit + coût regex. */
const MAX_LINE_LENGTH = 2000;

// ---------------------------------------------------------------------------
// Commandes dangereuses — scripts shell et instructions de documentation.
// Ce sont les commandes qu'un hacker fait exécuter à sa victime (packages
// malveillants, README piégés, gists, réponses de forums).
// ---------------------------------------------------------------------------
const DANGEROUS_COMMANDS: AttackRule[] = [
  {
    id: 'ATK-CMD-001',
    aggregate: true,
    name: 'curl | bash (exécution de code distant)',
    regex: /(curl|wget)\s[^|\n]*\|\s*(sudo\s+)?(ba|z|da)?sh\b/g,
    severity: 'critical',
    attack: 'Le script distant s\'exécute immédiatement avec vos droits. Si le domaine est compromis, expiré ou détourné (MITM en HTTP), une backdoor s\'installe en une seconde.',
    prevention: 'Téléchargez le script, lisez-le, vérifiez son checksum, puis exécutez-le. Méfiez-vous de toute doc qui impose curl | bash.',
    inDocs: true,
  },
  {
    id: 'ATK-CMD-002',
    aggregate: true,
    name: 'Payload base64 exécuté',
    regex: /base64\s+(-d|--decode|-D)[^|\n]*\|\s*(ba)?sh\b|echo\s+['"]?[A-Za-z0-9+/=]{60,}['"]?\s*\|\s*base64/g,
    severity: 'high',
    attack: 'La vraie commande est cachée en base64 pour échapper aux antivirus et à votre vigilance — décodée, c\'est souvent un stealer ou un reverse shell.',
    prevention: 'Décodez d\'abord SANS exécuter (base64 -d seul) pour inspecter. Tout code obfusqué est suspect par défaut.',
    inDocs: true,
  },
  {
    id: 'ATK-CMD-003',
    name: 'eval sur du contenu distant',
    regex: /eval\s+["']?\$\((curl|wget)|eval\s+\$\((curl|wget)/g,
    severity: 'critical',
    attack: 'eval exécute ce que le serveur renvoie, quoi qu\'il arrive. Compromission du domaine ou du DNS = exécution arbitraire sur votre machine.',
    prevention: 'Jamais d\'eval sur du contenu réseau. Téléchargez, inspectez, épinglez une version.',
    inDocs: true,
  },
  {
    id: 'ATK-CMD-004',
    name: 'Reverse shell',
    regex: /\/dev\/tcp\/\d|nc\s+[^;\n]*-e\s|ncat\s+[^;\n]*-e\s|mkfifo[^;\n]*\bnc\s/g,
    severity: 'critical',
    attack: 'Ouvre un shell inverse vers la machine du hacker : il pilote votre terminal à distance, souvent invisible pour les antivirus.',
    prevention: 'AUCUN code légitime n\'ouvre de reverse shell. Supprimez et auditez la machine (persistence, historique, processus).',
    inDocs: true,
  },
  {
    id: 'ATK-CMD-005',
    name: 'Exfiltration de fichiers sensibles',
    regex: /curl\s+[^|\n;]*(-F|-d|--data)[^|\n;]*@?\.?(env\b|id_rsa|\.ssh|\.aws|\.npmrc|credentials)|webhook\.site|requestbin|pipedream\.com|burpcollaborator|oastify\.com|interact\.sh/gi,
    severity: 'critical',
    attack: 'Envoie vos secrets (.env, clés SSH, tokens npm/AWS) vers un serveur du hacker. Technique signature des packages npm malveillants (event-stream, ua-parser-js).',
    prevention: 'Ce motif = compromission quasi certaine. Révoquez les secrets exposés, auditez les accès, bloquez ces domaines en CI.',
  },
  {
    id: 'ATK-CMD-006',
    aggregate: true,
    name: 'Commande destructive',
    regex: /rm\s+-[a-z]*[rf][a-z]*\s+(\/|~|\$HOME|\*)(\s|$)|dd\s+if=[^\n]*of=\/dev\/(sd|nvme|disk)|mkfs\.[a-z0-9]+|:\(\)\s*\{\s*:\|:&\s*\}\s*;:/gi,
    severity: 'critical',
    attack: 'Efface le disque, sature le système (fork bomb) ou formate une partition. Classique des scripts « d\'installation » piégés partagés sur les forums.',
    prevention: 'Ne copiez-collez jamais une commande comprise à moitié. Testez dans une VM jetable. Sauvegardes hors ligne.',
    inDocs: true,
  },
  {
    id: 'ATK-CMD-007',
    aggregate: true,
    name: 'chmod 777',
    regex: /chmod\s+(-R\s+)?777\s+(\/|\.|\*|\$)/g,
    severity: 'medium',
    attack: 'Tout le monde peut modifier et exécuter ces fichiers : n\'importe quel processus compromis y injecte une backdoor.',
    prevention: 'Moindre privilège : 755 pour les exécutables, 644 pour les fichiers, jamais 777.',
  },
  {
    id: 'ATK-CMD-008',
    aggregate: true,
    name: 'PowerShell encodé / Invoke-Expression',
    // `\s+[^|\n;]*\s-` exigeait DEUX espaces avant -enc : `powershell -enc …`,
    // la forme la plus courante, passait à travers.
    regex: /powershell(\.exe)?\b[^|\n;]*\s-(enc|ec|e)\s+[A-Za-z0-9+/=]{20,}|\bIEX\s*\(|Invoke-Expression|DownloadString/gi,
    severity: 'high',
    attack: 'Technique n°1 des malwares Windows : commande encodée + IEX télécharge et exécute un payload en mémoire (fileless, peu détecté).',
    prevention: 'Activez le Script Block Logging. Bloquez powershell -enc via AppLocker/WDAC. Tout -enc est suspect.',
  },
  {
    id: 'ATK-CMD-009',
    aggregate: true,
    name: 'Téléchargement via binaire Windows légitime (LOLBin)',
    regex: /certutil\s+[^|\n;]*-urlcache|bitsadmin\s+\/transfer|mshta(\.exe)?\s+https?:\/\/|rundll32\s+[^|\n;]*javascript/gi,
    severity: 'high',
    attack: 'certutil, bitsadmin ou mshta sont signés Microsoft : les malwares s\'en servent pour télécharger des payloads en contournant la confiance des antivirus.',
    prevention: 'Surveillez l\'usage de ces binaires hors administration. Restreignez via WDAC/AppLocker.',
  },
];

// ---------------------------------------------------------------------------
// Règles par type de fichier : la chaîne d'approvisionnement de chaque
// écosystème a son point d'entrée favori pour un hacker.
// ---------------------------------------------------------------------------
const FILE_RULES: FileRuleSet[] = [
  {
    match: /(^|[\\/])package\.json$/,
    rules: [
      {
        id: 'ATK-NPM-001',
    aggregate: true,
        name: 'Script exécuté à l\'installation npm',
        regex: /"(preinstall|install|postinstall|prepare)"\s*:/g,
        severity: 'medium',
        attack: 'Ces scripts s\'exécutent AUTOMATIQUEMENT au npm install — vecteur n°1 des packages malveillants (vol de .env, de tokens, miners).',
        prevention: 'npm install --ignore-scripts par défaut (ignore-scripts=true dans .npmrc). Auditez les scripts de chaque nouvelle dépendance.',
      },
      {
        id: 'ATK-NPM-002',
        name: 'Script d\'installation avec réseau ou shell',
        regex: /"(preinstall|install|postinstall|prepare)"\s*:\s*"[^"]*(curl|wget|powershell|cmd\b|node\s+-e|base64|\|\s*(ba)?sh)/gi,
        severity: 'critical',
        attack: 'Un script d\'install qui télécharge ou exécute du code externe = signature des compromises npm (node-ipc, coa, rc).',
        prevention: 'Auditez le script en entier avant toute exécution. Exigez une revue sécurité. Envisagez de bloquer cette dépendance.',
      },
      {
        id: 'ATK-NPM-003',
        name: 'Dépendance depuis une source non vérifiable',
        regex: /:\s*"(git\+http:\/\/|git:\/\/|http:\/\/[^"]*\.tgz|file:\.\.\/)/g,
        severity: 'high',
        attack: 'HTTP = contenu remplaçable par MITM ; .tgz/file: échappent au lockfile et aux scans du registry ; un repo git peut changer APRÈS votre revue.',
        prevention: 'Registry officiel en HTTPS + lockfile avec hashes d\'intégrité (npm ci en CI).',
      },
    ],
  },
  {
    match: /(^|[\\/])\.npmrc$/,
    rules: [
      {
        id: 'ATK-NPM-004',
        name: 'Registry npm en HTTP',
        regex: /registry\s*=\s*http:\/\//g,
        severity: 'high',
        attack: 'Trafic en clair : un attaquant sur le réseau remplace les packages téléchargés par des versions backdoorées.',
        prevention: 'HTTPS uniquement. Vérifiez les champs integrity du lockfile.',
      },
      {
        id: 'ATK-NPM-005',
        name: 'Token npm commité',
        regex: /_authToken\s*=\s*\S+/g,
        severity: 'critical',
        attack: 'Ce token permet de PUBLIER des versions malveillantes de vos packages — tous vos utilisateurs sont compromis en cascade.',
        prevention: 'Retirez le token du fichier versionné, révoquez-le sur npmjs.com, passez par des variables d\'environnement.',
      },
    ],
  },
  {
    match: /(^|[\\/])requirements[^\\/]*\.txt$/,
    rules: [
      {
        id: 'ATK-PY-001',
        name: 'Dépendance pip depuis git+http',
        regex: /git\+http:\/\/|^-e\s+git\+http:\/\//g,
        severity: 'high',
        attack: 'HTTP = MITM possible ; un repo git peut être modifié après votre revue, contrairement à une version PyPI pinnée avec hash.',
        prevention: 'PyPI + versions épinglées + hashes (pip install --require-hashes, pip-tools, uv).',
      },
      {
        id: 'ATK-PY-002',
        name: 'Index pip supplémentaire (dependency confusion)',
        regex: /--extra-index-url|--index-url\s+http(?!s)/g,
        severity: 'high',
        attack: 'Le hacker publie un package du MÊME NOM en version plus haute sur l\'index public : pip installe le sien (attaque Birsan 2021 — Apple, Microsoft, Tesla…).',
        prevention: 'Évitez --extra-index-url ; sinon noms internes uniques + pip-audit + index interne en HTTPS.',
      },
    ],
  },
  {
    match: /(^|[\\/])setup\.py$/,
    rules: [
      {
        id: 'ATK-PY-003',
        name: 'Code exécuté pendant pip install',
        regex: /os\.system|subprocess|urllib\.request|requests\.(get|post)|socket\./g,
        severity: 'high',
        attack: 'setup.py s\'exécute à l\'installation — les packages PyPI malveillants y cachent leurs downloaders (affaires jeilfire, colourama…).',
        prevention: 'Un setup.py ne doit contenir QUE des métadonnées. Préférez pyproject.toml (PEP 517) et les wheels.',
      },
    ],
  },
  {
    match: /(^|[\\/])[Mm]akefile(\.[a-z]+)?$/,
    rules: [
      {
        id: 'ATK-MK-001',
        name: 'Téléchargement exécuté par make',
        regex: /(curl|wget)[^\n]*(\|\s*(ba)?sh\b|>\s*\S+\.sh|-O\s*\S+\.sh)/g,
        severity: 'high',
        attack: 'make install/setup s\'exécute en confiance après un git clone — un dépôt piégé y cache un downloader.',
        prevention: 'Lisez le Makefile avant le premier make. Vérifiez les checksums des artefacts téléchargés.',
      },
    ],
  },
  {
    match: /(^|[\\/])build\.rs$/,
    rules: [
      {
        id: 'ATK-RS-001',
        name: 'Exécution ou réseau dans build.rs',
        regex: /Command::new|std::net|TcpStream|reqwest|ureq/g,
        severity: 'high',
        attack: 'build.rs s\'exécute à CHAQUE cargo build avec vos droits : une crate malveillante y exfiltre ~/.ssh, ~/.aws et vos variables d\'env.',
        prevention: 'Auditez les build.rs des crates (cargo vet, cargo-geiger). Buildez en conteneur sans réseau.',
      },
    ],
  },
  {
    match: /(^|[\\/])Gemfile$/,
    rules: [
      {
        id: 'ATK-RB-001',
        name: 'Gem depuis git en HTTP',
        regex: /git:\s*['"]http:\/\/|git_source\s*\{[^}]*http:\/\//g,
        severity: 'high',
        attack: 'Source en clair modifiable par MITM ; un repo git peut changer après revue.',
        prevention: 'rubygems.org en HTTPS + Gemfile.lock commité + bundler-audit.',
      },
    ],
  },
  {
    match: /(^|[\\/])composer\.json$/,
    rules: [
      {
        id: 'ATK-PHP-001',
        name: 'Script composer avec shell ou PHP arbitraire',
        regex: /"(pre|post)-(install|update)-cmd"\s*:\s*(\[?\s*"[^"]*(@php|sh\b|bash|curl|wget))/gi,
        severity: 'high',
        attack: 'Les scripts composer s\'exécutent à l\'install — vecteur documenté de webshells déposés par des packages PHP malveillants.',
        prevention: 'composer install --no-scripts en CI, puis exécution manuelle contrôlée des scripts légitimes.',
      },
    ],
  },
];

const SCRIPT_FILES = /\.(sh|bash|zsh|ps1|bat|cmd)$/i;
const DOC_FILES = /\.(md|markdown)$/i;

/** Fichiers que ce module sait analyser. */
export const ATTACK_FILE_TYPES =
  /(^|[\\/])(package\.json|\.npmrc|requirements[^\\/]*\.txt|setup\.py|[Mm]akefile(\.[a-z]+)?|build\.rs|Gemfile|composer\.json|\.gitignore)$|\.(sh|bash|zsh|ps1|bat|cmd|md|markdown)$/i;

function toFinding(rule: AttackRule, relPath: string, line: number): Finding {
  return {
    kind: 'attack',
    severity: rule.severity,
    id: rule.id,
    title: `${rule.name} (${rule.id})`,
    description: `🥷 ATTAQUE : ${rule.attack}\n\n🛡️ PRÉVENTION : ${rule.prevention}`,
    file: relPath,
    line,
  };
}

/**
 * Cherche les vecteurs d'attaque dans le contenu d'un fichier déjà lu.
 * Comme secrets.ts : regex en /g + matchAll (pas de lastIndex partagé).
 */
export function scanAttackInText(fsPath: string, relPath: string, text: string): Finding[] {
  const findings: Finding[] = [];
  const lines = text.split(/\r?\n/);
  const isDoc = DOC_FILES.test(fsPath);
  const isScript = SCRIPT_FILES.test(fsPath);

  const apply = (rules: AttackRule[]): void => {
    lines.forEach((line, i) => {
      if (line.length > MAX_LINE_LENGTH) return;
      for (const rule of rules) {
        if (isDoc && !rule.inDocs) continue;
        for (const _m of line.matchAll(rule.regex)) {
          findings.push(toFinding(rule, relPath, i + 1));
        }
      }
    });
  };

  if (isScript || isDoc) apply(DANGEROUS_COMMANDS);
  for (const set of FILE_RULES) {
    if (set.match.test(fsPath)) apply(set.rules);
  }

  // Un .gitignore qui ne couvre pas .env : recommandation préventive.
  //
  // Volontairement en `medium`, pas en `critical` : ce module ne voit qu'un
  // fichier à la fois et ignore si un .env existe réellement. Sans cette
  // nuance, tout projet sans .env — Nodock lui-même — remontait une alerte
  // critique. C'est audit.ts (NDK-AUD-001) qui escalade en critique lorsqu'un
  // .env est effectivement présent et non ignoré.
  if (
    /(^|[\\/])\.gitignore$/.test(fsPath) &&
    !/^\s*\*?\*?\/?\.env/m.test(text) &&
    !/^\s*\*\.env/m.test(text)
  ) {
    findings.push({
      kind: 'attack',
      severity: 'medium',
      id: 'ATK-GIT-001',
      title: '.env non exclu de git (ATK-GIT-001)',
      description:
        '🥷 ATTAQUE : un .env commité reste dans l\'historique git pour toujours. Les bots scannent les forges publiques en continu et vident les comptes cloud en quelques minutes.\n\n' +
        '🛡️ PRÉVENTION : ajoutez `.env`, `.env.*`, `*.pem` et `id_rsa` au .gitignore dès maintenant — avant qu\'un fichier de ce type n\'apparaisse. Si un .env a déjà été commité : révoquez TOUTES les clés, puis purgez l\'historique (git filter-repo).',
      file: relPath,
      line: 1,
    });
  }

  return findings;
}

/**
 * Regroupe les motifs systémiques en un finding par règle.
 *
 * Les outils tiers embarqués répètent le même script d'installation dans chaque
 * dossier : 23 alertes `curl | bash` identiques décrivent une seule décision.
 */
export function aggregateAttack(findings: Finding[]): Finding[] {
  const aggregatable = new Set(
    [...DANGEROUS_COMMANDS, ...FILE_RULES.flatMap((s) => s.rules)]
      .filter((r) => r.aggregate)
      .map((r) => r.id)
  );

  const byRule = new Map<string, Finding[]>();
  const out: Finding[] = [];

  for (const f of findings) {
    if (!aggregatable.has(f.id ?? '')) {
      out.push(f);
      continue;
    }
    const list = byRule.get(f.id ?? '');
    if (list) list.push(f);
    else byRule.set(f.id ?? '', [f]);
  }

  for (const [, group] of byRule) {
    if (group.length === 1) {
      out.push(group[0]);
      continue;
    }
    const files = [...new Set(group.map((f) => f.file ?? ''))];
    const shown = files.slice(0, 8).map((f) => `• ${f}`).join('\n');
    const more = files.length > 8 ? `\n• … et ${files.length - 8} autre(s)` : '';

    out.push({
      ...group[0],
      title: `${group[0].title} — ${group.length} occurrence(s) dans ${files.length} fichier(s)`,
      description: `${group[0].description}\n\n**Où (${files.length} fichiers)**\n${shown}${more}`,
    });
  }

  return out;
}
