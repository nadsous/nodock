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
  /** Actions techniques concrètes, dans l'ordre où les faire. */
  todo?: string[];
  /** Texte prêt à coller dans les mentions légales / la politique de confidentialité. */
  disclosure?: string;
}

/** Actions et texte à déclarer, par règle. Séparés du tableau pour la lisibilité. */
const GUIDANCE: Record<string, { todo: string[]; disclosure: string }> = {
  'CMP-001': {
    todo: [
      'Ne chargez le script Google qu\'APRÈS un consentement explicite (pas au chargement de la page).',
      'Activez l\'anonymisation IP : gtag("config", "G-XXX", { anonymize_ip: true }).',
      'Désactivez Google Signals et la personnalisation des annonces si vous n\'en avez pas besoin.',
      'Signez le Data Processing Amendment dans l\'admin Google Analytics.',
      'Prévoyez un moyen de retirer son consentement aussi simple que de le donner.',
    ],
    disclosure:
      'Mesure d\'audience : nous utilisons Google Analytics (Google Ireland Ltd, avec transfert vers Google LLC aux États-Unis encadré par le EU-US Data Privacy Framework). '
      + 'Finalité : mesurer la fréquentation du site. Base légale : votre consentement. '
      + 'Durée de conservation : [14 mois maximum]. Vous pouvez retirer votre consentement à tout moment via [lien vers vos préférences cookies].',
  },
  'CMP-002': {
    todo: [
      'Aucun cookie non essentiel ne doit être déposé avant le clic sur « Accepter ».',
      'Le bouton « Refuser » doit être au même niveau visuel que « Accepter » (exigence CNIL).',
      'Fixez une durée de vie ≤ 13 mois et un consentement redemandé au bout de 6 mois.',
      'Tenez la liste de vos cookies : nom, finalité, durée, émetteur.',
    ],
    disclosure:
      'Cookies : ce site dépose des cookies [techniques / de mesure d\'audience / publicitaires]. '
      + 'Les cookies non essentiels ne sont déposés qu\'après votre consentement. '
      + 'Vous pouvez modifier vos choix à tout moment via [lien]. Durée de conservation : [13 mois maximum].',
  },
  'CMP-003': {
    todo: [
      'Distinguez le strictement nécessaire (panier, session, préférence de thème) du reste : seul le second exige un consentement.',
      'Ne stockez aucun identifiant publicitaire ou de traçage sans consentement préalable.',
      'Purgez les données au bout d\'une durée définie — localStorage n\'expire jamais tout seul.',
      'Ne stockez jamais de token d\'authentification en localStorage (préférez un cookie httpOnly).',
    ],
    disclosure:
      'Stockage local : nous conservons dans votre navigateur [préférences d\'affichage / panier / identifiant de session] '
      + 'afin de [finalité]. Ces données restent sur votre appareil et sont conservées [durée]. '
      + 'Vous pouvez les effacer en vidant le stockage local de votre navigateur.',
  },
  'CMP-004': {
    todo: [
      'Affichez la finalité au moment même de la collecte, à côté du champ (pas seulement dans une page séparée).',
      'Ajoutez une case à cocher NON pré-cochée si la donnée sert au marketing.',
      'Indiquez le caractère obligatoire ou facultatif de chaque champ.',
      'Mettez en place une procédure de suppression sur demande (et testez-la).',
    ],
    disclosure:
      'Données collectées via nos formulaires : [email, nom, …]. Finalité : [création de compte / newsletter / contact]. '
      + 'Base légale : [consentement / exécution du contrat]. Destinataires : [prestataires, ex. Mailchimp (USA)]. '
      + 'Durée de conservation : [3 ans à compter du dernier contact]. '
      + 'Vous disposez d\'un droit d\'accès, de rectification, d\'effacement, de portabilité et d\'opposition en écrivant à [email].',
  },
  'CMP-005': {
    todo: [
      'Ne chargez le pixel qu\'après consentement — la simple présence du script déclenche la collecte.',
      'Listez nommément chaque tiers dans votre politique de confidentialité.',
      'Pour les visiteurs californiens : publiez un lien « Do Not Sell or Share My Personal Information » et respectez le signal GPC.',
      'Vérifiez si un accord de responsabilité conjointe est requis (cas du Meta Pixel).',
    ],
    disclosure:
      'Traceurs publicitaires : nous utilisons [Meta Pixel / Hotjar / Mixpanel / Clarity] pour [mesurer nos campagnes / analyser la navigation]. '
      + 'Ces outils déposent des cookies et transmettent des données à [éditeur], y compris hors de l\'Union européenne. '
      + 'Base légale : votre consentement. Vous pouvez vous y opposer via [lien].',
  },
  'CMP-006': {
    todo: [
      'Demandez la position au moment de l\'action de l\'utilisateur, jamais au chargement de la page.',
      'Expliquez pourquoi vous en avez besoin AVANT d\'ouvrir la popup du navigateur.',
      'Limitez la précision au strict nécessaire (une ville suffit souvent à une géolocalisation précise au mètre).',
      'Ne conservez pas l\'historique des positions au-delà de l\'usage immédiat.',
    ],
    disclosure:
      'Géolocalisation : avec votre accord, nous utilisons votre position pour [afficher les points de vente proches]. '
      + 'La position n\'est pas conservée au-delà de [durée] et n\'est jamais transmise à des tiers. '
      + 'Vous pouvez révoquer cette autorisation dans les réglages de votre navigateur.',
  },
  'CMP-007': {
    todo: [
      'Déclenchez l\'accès sur une action explicite, et affichez un indicateur visible pendant la captation.',
      'Si vous faites de la reconnaissance faciale ou vocale, vous traitez des données biométriques : une analyse d\'impact (AIPD) est obligatoire.',
      'Privilégiez un traitement local, sans envoi des flux au serveur.',
      'Coupez explicitement les pistes (track.stop()) dès la fin de l\'usage.',
    ],
    disclosure:
      'Caméra et microphone : utilisés uniquement pour [visioconférence / photo de profil], sur votre action et avec votre autorisation. '
      + 'Les flux [ne sont pas enregistrés / sont conservés durée]. Aucun traitement biométrique n\'est effectué.',
  },
  'CMP-008': {
    todo: [
      'Recensez chaque destinataire externe dans votre registre des traitements (article 30).',
      'Signez un contrat de sous-traitance (article 28) avec chaque prestataire.',
      'Pour les transferts hors UE, vérifiez les garanties : clauses contractuelles types ou Data Privacy Framework.',
      'Envoyez le strict nécessaire : ne transmettez pas l\'objet utilisateur complet quand un identifiant suffit.',
    ],
    disclosure:
      'Destinataires des données : [liste des prestataires et de leur pays]. '
      + 'Ces prestataires agissent comme sous-traitants et sont contractuellement tenus de ne traiter vos données que sur nos instructions. '
      + 'Transferts hors UE encadrés par [clauses contractuelles types / EU-US Data Privacy Framework].',
  },
  'CMP-009': {
    todo: [
      'Déterminez l\'âge minimum de votre service et vérifiez-le (15 ans en France pour un consentement autonome, 13 ans aux USA).',
      'En dessous, recueillez un consentement parental vérifiable — une simple case à cocher ne suffit pas au regard de COPPA.',
      'Désactivez tout profilage publicitaire pour les comptes mineurs.',
      'Appliquez les réglages de confidentialité les plus protecteurs par défaut.',
    ],
    disclosure:
      'Mineurs : notre service s\'adresse aux personnes de [âge] ans et plus. '
      + 'Pour les utilisateurs de moins de [15] ans, le consentement du titulaire de l\'autorité parentale est requis et vérifié via [procédure]. '
      + 'Aucune publicité ciblée n\'est diffusée aux comptes mineurs.',
  },
  'CMP-010': {
    todo: [
      'Les données de santé relèvent de l\'article 9 du RGPD : leur traitement est interdit sauf exception — identifiez la vôtre.',
      'Une analyse d\'impact (AIPD) est obligatoire.',
      'En France, l\'hébergement doit être certifié HDS (Hébergeur de Données de Santé).',
      'Chiffrez au repos et en transit, et journalisez chaque accès de façon inaltérable.',
    ],
    disclosure:
      'Données de santé : nous traitons [nature des données] pour [finalité]. '
      + 'Base légale : [article 9.2.a consentement explicite / 9.2.h médecine préventive]. '
      + 'Hébergement : [hébergeur certifié HDS]. Durée de conservation : [durée légale applicable]. '
      + 'Ces données ne sont accessibles qu\'aux personnels habilités et chaque accès est journalisé.',
  },
};

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
    files: /\.(html?|js|ts|jsx|tsx|vue|svelte|json)$/,
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
    files: /\.(js|ts|jsx|tsx|py|json|ya?ml)$/,
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
  return laws.map((l) => `\n⚖️ **${l.law}** : ${l.req}`).join('');
}

/**
 * Compose une consigne lisible : ce qui a été détecté, ce qu'il faut FAIRE,
 * ce qu'il faut ÉCRIRE, et seulement ensuite le détail par juridiction.
 * L'ordre compte : l'utilisateur veut d'abord savoir quoi faire.
 */
function describe(rule: ComplianceRule, locations: string[]): string {
  const guidance = GUIDANCE[rule.id];
  const parts: string[] = [`**Détecté** — ${rule.description}`];

  if (guidance?.todo?.length) {
    parts.push(
      '**Ce que vous devez faire**\n' +
        guidance.todo.map((t, i) => `${i + 1}. ${t}`).join('\n')
    );
  }

  if (guidance?.disclosure) {
    parts.push(
      '**À ajouter dans vos mentions légales** (adaptez les [crochets])\n' +
        `> ${guidance.disclosure}`
    );
  }

  if (locations.length > 0) {
    const shown = locations.slice(0, 8).map((l) => `• ${l}`).join('\n');
    const more = locations.length > 8 ? `\n• … et ${locations.length - 8} autre(s)` : '';
    parts.push(`**Où (${locations.length})**\n${shown}${more}`);
  }

  parts.push(`**Selon la juridiction**${formatLaws(rule.laws)}`);
  return parts.join('\n\n');
}

/**
 * Regroupe les findings de conformité par règle, pour l'ensemble du projet.
 *
 * L'obligation légale est projet-wide : utiliser localStorage dans neuf
 * composants ne crée pas neuf obligations, mais une seule. Répéter l'alerte
 * par fichier noyait le rapport sans rien apporter.
 */
export function aggregateCompliance(findings: Finding[]): Finding[] {
  const byRule = new Map<string, Finding[]>();
  for (const f of findings) {
    const list = byRule.get(f.id ?? '');
    if (list) list.push(f);
    else byRule.set(f.id ?? '', [f]);
  }

  const out: Finding[] = [];
  for (const [id, group] of byRule) {
    const rule = RULES.find((r) => r.id === id);
    if (!rule) {
      out.push(...group);
      continue;
    }
    const locations = group.map((f) => `${f.file}${f.line ? `:${f.line}` : ''}`);
    out.push({
      ...group[0],
      title: `${rule.name} (${rule.id})`,
      description: describe(rule, locations),
    });
  }
  return out;
}

/**
 * Extensions analysées pour la conformité.
 * Le Markdown en est exclu : la conformité porte sur ce que le CODE fait, pas
 * sur ce que la documentation mentionne. Scanner les .md ne produisait que des
 * faux positifs (guides d'intégration, exemples de schémas).
 */
export const RGPD_FILE_TYPES = /\.(html?|js|ts|jsx|tsx|mjs|cjs|vue|svelte|py|json|ya?ml)$/i;

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
          // Description provisoire : aggregateCompliance() la reconstruit avec
          // tous les emplacements une fois le projet entièrement parcouru.
          description: rule.description,
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
