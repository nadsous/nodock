export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

/** Ce qu'il faut chercher dans le code pour savoir si une faille est atteignable. */
export interface TriageProbe {
  pkg: string;
  /** Sous-chemins d'import cités par l'avis, ex. 'better-auth/plugins/mcp'. */
  subpaths: string[];
  /** Symboles/API cités par l'avis, ex. 'oidcProvider', 'template'. */
  symbols: string[];
}

/** Verdict d'atteignabilité. `improbable` ne signifie jamais « non vulnérable ». */
export interface Triage {
  verdict: 'probable' | 'a-verifier' | 'improbable';
  reasons: string[];
}

export interface Finding {
  kind:
    | 'dependency'
    | 'secret'
    | 'sast'
    | 'websec'
    | 'infra'
    | 'attack'
    | 'rgpd'
    | 'standards'
    | 'audit';
  severity: Severity;
  title: string;
  description: string;
  file?: string;
  line?: number;
  /** Package concerné (pour les dépendances) */
  package?: string;
  version?: string;
  /** Version qui corrige la vulnérabilité, si connue */
  fixedVersion?: string;
  /** CVE / GHSA / identifiant de règle */
  id?: string;
  url?: string;
  /** Version déduite d'un range faute de lockfile — résultat approximatif. */
  imprecise?: boolean;
  /** Score CVSS calculé, ex. "CVSS 7.5" */
  cvss?: string;
  /** CWE associées, ex. "CWE-79, CWE-400" */
  cwe?: string;
  /** Dépendance déclarée dans un manifeste (vs tirée en transitif). */
  direct?: boolean;
  /** API vulnérables à chercher dans le code (dépendances uniquement). */
  probe?: TriageProbe;
  /** Résultat du triage : ce finding concerne-t-il réellement ce projet ? */
  triage?: Triage;
}

export interface NewsItem {
  title: string;
  url: string;
  source: string;
  date: string;
  summary?: string;
}

export interface ScanReport {
  generatedAt: string;
  findings: Finding[];
  stats: {
    dependenciesScanned: number;
    filesScanned: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
  /** Avertissements non bloquants : troncature, module en échec, versions approximatives… */
  notes: string[];
  /** true si le scan a été interrompu par l'utilisateur. */
  cancelled?: boolean;
  /** Inventaire des dépendances installées, pour l'export SBOM. */
  components?: Array<{ name: string; version: string; ecosystem: string }>;
}

export const SEVERITY_ORDER: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];
