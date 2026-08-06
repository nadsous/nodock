import { Finding, Severity } from './types';

/**
 * Infrastructure : conteneurs et chaînes d'intégration.
 *
 * C'est la partie qu'on oublie d'auditer parce qu'elle n'est pas « du code »,
 * alors qu'elle s'exécute avec les privilèges les plus élevés du projet. Un
 * workflow CI compromis livre les secrets de production ; un conteneur en root
 * transforme une exécution de code en compromission de l'hôte.
 */

interface InfraRule {
  id: string;
  name: string;
  regex: RegExp;
  files: RegExp;
  severity: Severity;
  description: string;
  fix: string;
  /** Motif qui disculpe le match, testé sur le fichier entier. */
  exempt?: RegExp;
}

const DOCKERFILE = /(^|[\\/])(Dockerfile|Containerfile)([\w.-]*)$/i;
const COMPOSE = /(^|[\\/])(docker-)?compose[\w.-]*\.ya?ml$/i;
const WORKFLOW = /(^|[\\/])\.(github|gitea)[\\/]workflows[\\/][\w.-]+\.ya?ml$/i;
const GITLAB_CI = /(^|[\\/])\.gitlab-ci[\w.-]*\.ya?ml$/i;

const RULES: InfraRule[] = [
  // --- Conteneurs ---
  {
    id: 'INF-DOCK-001',
    name: 'Conteneur exécuté en root',
    regex: /^\s*(FROM|CMD|ENTRYPOINT)\b/im,
    // Un Dockerfile sans instruction USER laisse le processus en root.
    exempt: /^\s*USER\s+(?!root\b|0\b)\S+/im,
    files: DOCKERFILE,
    severity: 'high',
    description:
      'Aucune instruction `USER` non privilégiée : le processus tourne en root. Une exécution de code dans l\'application devient alors une prise de contrôle du conteneur, et l\'évasion vers l\'hôte s\'en trouve grandement facilitée.',
    fix: 'Ajoutez avant CMD :\nRUN adduser --disabled-password --gecos "" app\nUSER app',
  },
  {
    id: 'INF-DOCK-002',
    name: 'Image de base non épinglée',
    regex: /^\s*FROM\s+\S+:latest\b|^\s*FROM\s+[^\s:@]+\s*(AS\s+\w+)?\s*$/im,
    files: DOCKERFILE,
    severity: 'medium',
    description:
      'L\'image de base est en `latest` ou sans tag : deux constructions successives ne produisent pas le même résultat, et une image compromise en amont entre sans que rien ne le signale.',
    fix: 'Épinglez par empreinte : FROM node:22.11.0-alpine@sha256:… — reproductible et vérifiable.',
  },
  {
    id: 'INF-DOCK-003',
    name: 'Secret dans une instruction ENV ou ARG',
    regex: /^\s*(ENV|ARG)\s+\w*(PASSWORD|SECRET|TOKEN|API_?KEY|PRIVATE_?KEY|CREDENTIAL)\w*\s*[= ]\s*\S+/im,
    files: DOCKERFILE,
    severity: 'critical',
    description:
      'Un secret placé en ENV ou ARG est inscrit dans une couche de l\'image : il reste lisible par `docker history`, même supprimé dans une instruction ultérieure. Quiconque récupère l\'image récupère le secret.',
    fix: 'Injectez le secret à l\'exécution (variable d\'environnement du runtime, gestionnaire de secrets) ou utilisez `RUN --mount=type=secret` de BuildKit.',
  },
  {
    id: 'INF-DOCK-004',
    name: 'Vérification TLS désactivée à la construction',
    regex: /--no-check-certificate|--insecure\b|NODE_TLS_REJECT_UNAUTHORIZED\s*=?\s*0|\bcurl\b[^\n]*\s-k(\s|$)|\bwget\b[^\n]*\s--no-check/i,
    files: DOCKERFILE,
    severity: 'high',
    description:
      'Un téléchargement sans vérification TLS pendant la construction : le contenu installé dans l\'image peut être substitué par un intermédiaire réseau.',
    fix: 'Rétablissez la vérification et ajoutez le certificat racine nécessaire s\'il s\'agit d\'un miroir interne.',
  },
  {
    id: 'INF-COMP-001',
    name: 'Conteneur privilégié',
    regex: /^\s*privileged\s*:\s*true|^\s*-\s*['"]?SYS_ADMIN|cap_add\s*:\s*\[[^\]]*SYS_ADMIN/im,
    files: COMPOSE,
    severity: 'critical',
    description:
      'Le mode privilégié désactive l\'essentiel de l\'isolation : accès aux périphériques de l\'hôte, capacités complètes. L\'évasion du conteneur devient triviale.',
    fix: 'Retirez `privileged: true` et n\'ajoutez que les capacités strictement nécessaires via `cap_add`.',
  },
  {
    id: 'INF-COMP-002',
    name: 'Socket Docker monté dans un conteneur',
    regex: /\/var\/run\/docker\.sock/,
    files: COMPOSE,
    severity: 'critical',
    description:
      'Monter le socket Docker équivaut à donner les droits root sur l\'hôte : depuis le conteneur, on peut en démarrer un autre en montant tout le système de fichiers.',
    fix: 'Passez par une API intermédiaire à privilèges restreints, ou un proxy de socket filtrant les commandes autorisées.',
  },
  {
    id: 'INF-COMP-003',
    name: 'Port de base de données exposé sur l\'hôte',
    regex: /^\s*-\s*['"]?(0\.0\.0\.0:)?(5432|3306|27017|6379|9200|5984):\d+/im,
    files: COMPOSE,
    severity: 'high',
    description:
      'Un port de base de données publié sur toutes les interfaces est joignable depuis l\'extérieur si le pare-feu de l\'hôte laisse passer — configuration fréquente sur un serveur de développement exposé.',
    fix: 'Restreignez à la boucle locale (`127.0.0.1:5432:5432`) ou supprimez la publication : les services du même réseau Compose se joignent par leur nom.',
  },

  // --- Intégration continue ---
  {
    id: 'INF-CI-001',
    name: 'pull_request_target avec récupération du code de la PR',
    regex: /pull_request_target/,
    files: WORKFLOW,
    severity: 'critical',
    description:
      '`pull_request_target` s\'exécute avec les secrets du dépôt ET les droits en écriture. Combiné à un `checkout` de la branche proposée, n\'importe qui ouvrant une pull request peut faire exécuter son code avec vos secrets — c\'est l\'une des compromissions de chaîne d\'approvisionnement les plus exploitées.',
    fix: 'Utilisez `pull_request`. Si vous avez besoin des secrets, séparez en deux workflows : l\'un construit sans secret, l\'autre consomme l\'artefact via `workflow_run`.',
  },
  {
    id: 'INF-CI-002',
    name: 'Action tierce non épinglée',
    regex: /^\s*-?\s*uses\s*:\s*(?!actions\/|github\/)[\w.-]+\/[\w.-]+@(main|master|v?\d+(\.\d+)*)\s*$/im,
    files: WORKFLOW,
    severity: 'high',
    description:
      'Une action tierce référencée par branche ou par tag mobile : son auteur — ou quiconque compromet son compte — peut en changer le contenu à tout moment, et votre CI exécutera le nouveau code avec vos secrets.',
    fix: 'Épinglez par empreinte de commit : `uses: org/action@a1b2c3d4…` (le tag lisible peut rester en commentaire).',
  },
  {
    id: 'INF-CI-003',
    name: 'Permissions du jeton en écriture globale',
    regex: /^\s*permissions\s*:\s*write-all|^\s*contents\s*:\s*write\s*$/im,
    files: WORKFLOW,
    severity: 'medium',
    description:
      'Le jeton du workflow dispose de droits d\'écriture étendus. La moindre exécution de code dans la CI permet alors de réécrire le dépôt ou de publier une version.',
    fix: 'Déclarez `permissions: { contents: read }` par défaut et n\'élargissez que sur le job qui en a besoin.',
  },
  {
    id: 'INF-CI-004',
    name: 'Secret interpolé dans une commande shell',
    regex: /run\s*:[^\n]*\$\{\{\s*secrets\.[\w.]+\s*\}\}/i,
    files: WORKFLOW,
    severity: 'high',
    description:
      'Un secret interpolé directement dans un `run` se retrouve dans la ligne de commande : visible dans les traces d\'exécution, la liste des processus, et les journaux en cas d\'échec.',
    fix: 'Passez par l\'environnement : `env: { TOKEN: ${{ secrets.TOKEN }} }` puis utilisez `$TOKEN` dans le script.',
  },
  {
    id: 'INF-CI-005',
    name: 'Secret en clair dans la configuration CI',
    regex: /^\s*\w*(PASSWORD|SECRET|TOKEN|API_?KEY)\w*\s*:\s*['"]?[A-Za-z0-9_\-/+]{12,}['"]?\s*$/im,
    exempt: /\$\{\{|\$\{|\$[A-Z_]+|<[^>]+>|changeme|example/i,
    files: new RegExp(`${WORKFLOW.source}|${GITLAB_CI.source}`, 'i'),
    severity: 'critical',
    description:
      'Une valeur ressemblant à un secret est écrite en clair dans la configuration d\'intégration continue — donc versionnée et lisible par tous ceux qui accèdent au dépôt.',
    fix: 'Déplacez-la dans les secrets du dépôt et référencez-la, puis considérez la valeur actuelle comme compromise et révoquez-la.',
  },
];

/** Fichiers d'infrastructure à analyser. */
export const INFRA_FILE_TYPES = new RegExp(
  [DOCKERFILE.source, COMPOSE.source, WORKFLOW.source, GITLAB_CI.source].join('|'),
  'i'
);

const COMMENT = /^\s*#/;

/** Applique les règles d'infrastructure au contenu d'un fichier déjà lu. */
export function scanInfraInText(fsPath: string, relPath: string, text: string): Finding[] {
  const applicable = RULES.filter((r) => r.files.test(fsPath));
  if (applicable.length === 0) return [];

  const findings: Finding[] = [];
  const lines = text.split(/\r?\n/);

  for (const rule of applicable) {
    // Une exemption se juge sur le fichier entier : l'instruction USER peut
    // apparaître bien après le FROM qui a déclenché la règle.
    if (rule.exempt?.test(text)) continue;

    for (let i = 0; i < lines.length; i++) {
      if (COMMENT.test(lines[i])) continue;
      if (!rule.regex.test(lines[i])) continue;

      findings.push({
        kind: 'infra',
        severity: rule.severity,
        id: rule.id,
        title: `${rule.name} (${rule.id})`,
        description: `${rule.description}\n\n**Correctif**\n${rule.fix}`,
        file: relPath,
        line: i + 1,
      });
      break; // une occurrence par règle et par fichier suffit
    }
  }

  return findings;
}
