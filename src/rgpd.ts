import { Finding, Severity } from './types';

/** Exigence pour une juridiction donnée. */
interface LawReq {
  law: string;    // ex: "RGPD (UE)"
  req: string;    // ce qu'il faut déclarer / faire
}

interface ComplianceRule {
  id: string;
  name: string;
  regex: RegExp;
  severity: Severity;
  description: string;
  laws: LawReq[];
  files: RegExp;
}

const RULES: ComplianceRule[] = [
  {
    id: 'CMP-001',
    name: 'Google Analytics / Tag Manager',
    // L'ID GA4 fait exactement 10 caractères : `G-[A-Z0-9]{6,}` attrapait
    // n'importe quelle constante en majuscules préfixée par G-.
    regex: /(google-analytics\.com|googletagmanager\.com|\bgtag\s*\(|\bG-[A-Z0-9]{10}\b)/,
    severity: 'high',
    description: 'Mesure d\'audience Google détectée — transfert de données vers Google LLC (USA).',
    laws: [
      { law: 'RGPD (UE)', req: 'Bandeau de consentement AVANT dépôt (CNIL), anonymisation IP, DPA avec Google, mention du transfert hors UE (EU-US Data Privacy Framework).' },
      { law: 'UK GDPR / PECR (Royaume-Uni)', req: 'Consentement préalable aux cookies analytiques, politique cookies détaillée.' },
      { law: 'CCPA/CPRA (Californie)', req: 'Considéré comme "share" de données personnelles → lien "Do Not Sell or Share My Personal Information" obligatoire + Global Privacy Control (GPC) respecté.' },
      { law: 'Loi 25 (Québec)', req: 'Consentement explicite, registre des incidents de confidentialité, mention dans la politique de confidentialité.' },
      { law: 'LGPD (Brésil)', req: 'Base légale documentée (consentement ou intérêt légitime), droit d\'opposition, DPO désigné si traitement à grande échelle.' },
      { law: 'PIPL (Chine)', req: 'Consentement séparé pour le transfert transfrontalier de données + évaluation de sécurité si volumes importants.' },
    ],
    files: /\.(html?|js|ts|jsx|tsx|vue|svelte)$/,
  },
  {
    id: 'CMP-002',
    name: 'Cookie déposé',
    regex: /document\.cookie\s*=/,
    severity: 'medium',
    description: 'Dépôt de cookie côté client — tout cookie non essentiel exige un consentement préalable.',
    laws: [
      { law: 'RGPD / ePrivacy (UE)', req: 'Consentement préalable, refus aussi simple que l\'acceptation, durée max 13 mois (CNIL), liste complète des cookies dans la politique.' },
      { law: 'UK PECR (Royaume-Uni)', req: 'Consentement pour cookies non essentiels, information claire sur finalité et durée.' },
      { law: 'CCPA/CPRA (Californie)', req: 'Pas de consentement préalable requis mais opt-out obligatoire (lien Do Not Sell/Share) si cookies publicitaires.' },
      { law: 'PIPEDA (Canada)', req: 'Consentement implicite toléré pour cookies non sensibles, information claire requise.' },
      { law: 'LGPD (Brésil)', req: 'Consentement pour cookies non essentiels (orientation ANPD).' },
      { law: 'DPDP Act (Inde)', req: 'Consentement libre, éclairé et révocable ; notice en anglais + 22 langues indiennes sur demande.' },
    ],
    files: /\.(html?|js|ts|jsx|tsx|vue|svelte)$/,
  },
  {
    id: 'CMP-003',
    name: 'localStorage / sessionStorage',
    regex: /(localStorage|sessionStorage)\.setItem\s*\(/,
    severity: 'medium',
    description: 'Stockage local — assimilé aux cookies par la CNIL si lecture/écriture d\'identifiants.',
    laws: [
      { law: 'RGPD / ePrivacy (UE)', req: 'Consentement si non strictement nécessaire ; déclarer la nature des données stockées et leur durée.' },
      { law: 'CCPA/CPRA (Californie)', req: 'Si identifiants/trackers stockés → opt-out requis.' },
      { law: 'LGPD (Brésil)', req: 'Finalité et durée documentées dans la politique de confidentialité.' },
    ],
    files: /\.(html?|js|ts|jsx|tsx|vue|svelte)$/,
  },
  {
    id: 'CMP-004',
    name: 'Collecte d\'email / formulaire',
    regex: /<(input|form)[^>]*(type=["']email["']|name=["'][^"']*email)/i,
    severity: 'medium',
    description: 'Formulaire collectant des données personnelles (email).',
    laws: [
      { law: 'RGPD (UE)', req: 'Finalité affichée au moment de la collecte, base légale, durée de conservation, droits des personnes, contact DPO.' },
      { law: 'CCPA/CPRA (Californie)', req: '"Notice at Collection" : catégories de données collectées + finalités affichées AVANT la collecte.' },
      { law: 'PIPEDA / Loi 25 (Canada)', req: 'Consentement éclairé, finalité limitée, agent de protection des renseignements personnels désigné (Québec).' },
      { law: 'LGPD (Brésil)', req: 'Finalité spécifique et explicite, information sur le partage éventuel.' },
      { law: 'APPI (Japon)', req: 'Finalité d\'utilisation spécifiée et publiée, gestion sécurisée, procédure de divulgation.' },
      { law: 'POPIA (Afrique du Sud)', req: 'Traitement licite et minimal, information du responsable, Information Officer désigné.' },
    ],
    files: /\.(html?|jsx|tsx|vue|svelte)$/,
  },
  {
    id: 'CMP-005',
    name: 'Trackers / pixels tiers',
    // `pixel` seul matche devicePixelRatio, pixelSize… : on exige les domaines réels.
    regex: /(connect\.facebook\.net|facebook\.com\/tr|static\.hotjar\.com|hotjar\.(com|io)|cdn\.mixpanel|api\.mixpanel|segment\.(com|io)|clarity\.ms|tiktok\.com\/i18n\/pixel|snap\.sc\/static\/pixel|fbq\s*\(|_linkedin_partner_id)/i,
    severity: 'high',
    description: 'Tracker tiers (Meta Pixel, Hotjar, Mixpanel, Clarity…) — profilage publicitaire.',
    laws: [
      { law: 'RGPD (UE)', req: 'Consentement explicite AVANT chargement, liste des tiers dans la politique, transferts hors UE encadrés.' },
      { law: 'CCPA/CPRA (Californie)', req: '"Sale/Share" → lien "Do Not Sell or Share My Personal Information" + signal GPC obligatoire.' },
      { law: 'UK GDPR / PECR', req: 'Consentement préalable au dépôt du pixel.' },
      { law: 'Loi 25 (Québec)', req: 'Consentement exprès pour la géolocalisation et le profilage ; fonction de confidentialité activée par défaut.' },
      { law: 'LGPD (Brésil)', req: 'Consentement pour le profilage publicitaire, droit d\'opposition.' },
      { law: 'PIPL (Chine)', req: 'Consentement séparé + évaluation d\'impact pour le traitement automatisé/profilage.' },
      { law: 'PDPA (Singapour)', req: 'Consentement à la collecte, notification de la finalité, DNC Registry respecté.' },
    ],
    files: /\.(html?|js|ts|jsx|tsx|vue|svelte)$/,
  },
  {
    id: 'CMP-006',
    name: 'Géolocalisation',
    regex: /navigator\.geolocation|getCurrentPosition|watchPosition/,
    severity: 'high',
    description: 'Accès à la géolocalisation — donnée personnelle quasi-sensible dans la plupart des juridictions.',
    laws: [
      { law: 'RGPD (UE)', req: 'Consentement explicite, finalité précise, durée de conservation courte, précision limitée au nécessaire.' },
      { law: 'CCPA/CPRA (Californie)', req: 'Géolocalisation précise = "sensitive personal information" → droit de limitation ("Limit the Use of My Sensitive Personal Information").' },
      { law: 'Loi 25 (Québec)', req: 'Consentement EXPRÈS obligatoire pour la géolocalisation.' },
      { law: 'PIPL (Chine)', req: 'Donnée sensible → consentement séparé + évaluation d\'impact obligatoire.' },
      { law: 'LGPD (Brésil)', req: 'Base légale documentée, finalité spécifique.' },
    ],
    files: /\.(js|ts|jsx|tsx|vue|svelte)$/,
  },
  {
    id: 'CMP-007',
    name: 'Caméra / microphone',
    // `mediaDevices` seul apparaît dans des tests de support : on cible l'accès effectif.
    regex: /getUserMedia\s*\(|getDisplayMedia\s*\(/,
    severity: 'high',
    description: 'Accès caméra/micro — données biométriques potentielles.',
    laws: [
      { law: 'RGPD (UE)', req: 'Si identification biométrique → article 9 (données sensibles) : consentement EXPLICITE + DPIA obligatoire.' },
      { law: 'CCPA/CPRA (Californie)', req: 'Données biométriques = sensitive PI → droit de limitation + notice spécifique.' },
      { law: 'PIPL (Chine)', req: 'Biométrie = donnée sensible → consentement séparé, nécessité démontrée, stockage local recommandé.' },
      { law: 'DPDP Act (Inde)', req: 'Consentement explicite, droit d\'effacement.' },
    ],
    files: /\.(js|ts|jsx|tsx|vue|svelte)$/,
  },
  {
    id: 'CMP-008',
    name: 'Envoi de données vers un tiers',
    regex: /fetch\s*\(\s*['"`]https?:\/\/(?!localhost)|axios\.(post|put)\s*\(/,
    severity: 'low',
    description: 'Envoi réseau détecté — vérifiez la destination des données personnelles.',
    laws: [
      { law: 'RGPD (UE)', req: 'Registre des traitements, sous-traitants contractuellement encadrés (art. 28), transferts hors UE avec garanties (CCT, DPF).' },
      { law: 'CCPA/CPRA (Californie)', req: 'Contrats avec les "service providers", pas de revente sans opt-out.' },
      { law: 'LGPD (Brésil)', req: 'Transferts internationaux seulement vers pays adéquats ou avec garanties.' },
      { law: 'PIPL (Chine)', req: 'Transfert transfrontalier : certification, CCT chinoises ou évaluation CAC.' },
      { law: 'PDPA (Singapour)', req: 'Le destinataire étranger doit offrir une protection comparable.' },
    ],
    files: /\.(js|ts|jsx|tsx|vue|svelte)$/,
  },
  {
    id: 'CMP-009',
    name: 'Contenu ciblant les enfants',
    // `child` / `children` seuls sont partout (childNodes, props React, arbres) :
    // on exige des formulations qui désignent réellement un public mineur.
    // Pas de \b en tête : les identifiants sont souvent en camelCase
    // (requireParentalConsent), où aucune frontière de mot ne précède le terme.
    regex: /(coppa|for[_-]?kids|kids[_-]?mode|under[_-]?13|age[_-]?gate|age[_-]?verification|parental[_-]?(consent|control)|minor[_-]?consent|child[_-]?(account|safety|protection|privacy)|is[_-]?(kid|child)\b)/i,
    severity: 'high',
    description: 'Référence à un public enfant détectée — régimes spéciaux très stricts.',
    laws: [
      { law: 'COPPA (USA)', req: 'Consentement parental VÉRIFIABLE obligatoire avant toute collecte chez les <13 ans ; politique spécifique ; pas de profilage publicitaire.' },
      { law: 'RGPD (UE)', req: 'Consentement parental requis sous 16 ans (13-16 selon les États, 15 ans en France) ; Age-Appropriate Design recommandé.' },
      { law: 'UK (Age Appropriate Design Code)', req: 'Paramètres de confidentialité élevés par défaut, géolocalisation désactivée, pas de nudging.' },
    ],
    files: /\.(html?|js|ts|jsx|tsx|vue|svelte|json|md)$/,
  },
  {
    id: 'CMP-010',
    name: 'Données de santé',
    // `health` seul matche healthCheck / healthz : on cible le vocabulaire médical.
    regex: /\b(hipaa|fhir|\w*patient\w*|medical[_-]?record|health[_-]?(record|data|insurance|information)|diagnosis|prescription|phi[_-]?data)\b/i,
    severity: 'high',
    description: 'Référence à des données de santé — régimes les plus protecteurs.',
    laws: [
      { law: 'HIPAA (USA)', req: 'Si entité couverte : chiffrement, BAA avec sous-traitants, journalisation des accès, notification de breach sous 60 jours.' },
      { law: 'RGPD (UE)', req: 'Article 9 : interdit sauf exception ; DPIA obligatoire ; hébergement certifié HDS en France.' },
      { law: 'PIPL (Chine)', req: 'Données médicales = sensibles → consentement séparé + localisation en Chine si grand volume.' },
    ],
    files: /\.(js|ts|jsx|tsx|py|json|ya?ml|md)$/,
  },
];

/** Checklist conformité mondiale affichée dans chaque rapport. */
export const LEGAL_CHECKLIST: Array<{ title: string; description: string }> = [
  { title: '🇪🇺 RGPD (Union européenne)', description: 'Identité éditeur + hébergeur (LCEN), finalités et bases légales, durées de conservation, droits (accès/rectification/effacement/portabilité/opposition), contact DPO, registre des traitements, DPIA si traitement à risque, notification de breach sous 72h à la CNIL.' },
  { title: '🇬🇧 UK GDPR / PECR (Royaume-Uni)', description: 'Mêmes exigences que le RGPD + consentement cookies (PECR), UK Representative si pas d\'établissement au UK.' },
  { title: '🇺🇸 CCPA/CPRA (Californie)', description: 'Notice at Collection, lien "Do Not Sell or Share My Personal Information", respect du signal Global Privacy Control, droit de suppression/correction, section données sensibles, politique de non-discrimination.' },
  { title: '🇺🇸 COPPA (USA, enfants <13 ans)', description: 'Consentement parental vérifiable, politique enfants dédiée, collecte minimale, pas de publicité comportementale.' },
  { title: '🇺🇸 HIPAA (USA, santé)', description: 'Si données de santé d\'entités couvertes : BAA, chiffrement, logs d\'accès, breach notification 60 jours.' },
  { title: '🇨🇦 PIPEDA + Loi 25 (Canada/Québec)', description: 'Consentement éclairé, agent vie privée désigné, Privacy Impact Assessment pour transferts hors Québec, registre des incidents, confidentialité par défaut (Loi 25).' },
  { title: '🇧🇷 LGPD (Brésil)', description: 'Finalité spécifique, base légale, DPO (encarregado) désigné, droits similaires au RGPD, notification de breach à l\'ANPD.' },
  { title: '🇨🇳 PIPL (Chine)', description: 'Consentement séparé (données sensibles, transferts, profilage), localisation des données si grand volume, évaluation CAC, représentant local.' },
  { title: '🇯🇵 APPI (Japon)', description: 'Finalité d\'utilisation publiée, registre des transferts tiers, procédure de divulgation/correction, notification de breach au PPC.' },
  { title: '🇸🇬 PDPA (Singapour)', description: 'Consentement + notification, DPO désigné, protection comparable pour transferts, breach notification 3 jours si risque significatif.' },
  { title: '🇮🇳 DPDP Act (Inde)', description: 'Consentement libre et révocable, notice claire (anglais + langues locales), droits d\'effacement et de nomination, pas de traitement ciblant les enfants sans consentement parental.' },
  { title: '🇿🇦 POPIA (Afrique du Sud)', description: 'Information Officer enregistré, traitement minimal, consentement pour marketing direct, notification de breach à l\'Information Regulator.' },
  { title: '🇦🇺 Privacy Act (Australie)', description: 'APP Privacy Policy, collecte nécessaire uniquement, opt-out marketing, Notifiable Data Breaches (OAIC).' },
  { title: '🍪 Politique cookies (globale)', description: 'Bandeau AVANT dépôt (UE/UK), liste des cookies + finalités + durées (max 13 mois CNIL), refus aussi simple que l\'acceptation, opt-out visible (USA).' },
];

function formatLaws(laws: LawReq[]): string {
  return laws.map((l) => `\n\n⚖️ **${l.law}** : ${l.req}`).join('');
}

/** Extensions pour lesquelles au moins une règle de conformité existe. */
export const RGPD_FILE_TYPES = /\.(html?|js|ts|jsx|tsx|mjs|cjs|vue|svelte|py|json|ya?ml|md)$/i;

/**
 * Applique les règles de conformité au contenu d'un fichier déjà lu.
 * Une règle n'est signalée qu'une fois par fichier (première occurrence).
 */
export function scanRgpdInText(fsPath: string, relPath: string, text: string): Finding[] {
  const applicable = RULES.filter((r) => r.files.test(fsPath));
  if (applicable.length === 0) return [];

  const findings: Finding[] = [];
  const lines = text.split(/\r?\n/);

  for (const rule of applicable) {
    for (let i = 0; i < lines.length; i++) {
      rule.regex.lastIndex = 0;
      if (rule.regex.test(lines[i])) {
        findings.push({
          kind: 'rgpd',
          severity: rule.severity,
          id: rule.id,
          title: `${rule.name} (${rule.id})`,
          description: `${rule.description}${formatLaws(rule.laws)}`,
          file: relPath,
          line: i + 1,
        });
        break; // une occurrence par règle et par fichier suffit
      }
    }
  }

  return findings;
}

/** Checklist juridique ajoutée à la fin de chaque rapport, à titre informatif. */
export function legalChecklistFindings(): Finding[] {
  return LEGAL_CHECKLIST.map((item) => ({
    kind: 'rgpd' as const,
    severity: 'info' as const,
    id: 'LEGAL',
    title: item.title,
    description: item.description,
  }));
}
