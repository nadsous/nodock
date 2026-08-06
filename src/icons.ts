import { ICON_PATHS } from './icons-data';

/**
 * Icônes du panneau (Lucide, licence ISC), injectées inline dans le webview
 * — la CSP `default-src 'none'` interdit tout fichier externe.
 *
 * Les chemins SVG sont extraits À LA COMPILATION par scripts/build-icons.cjs.
 * Les lire depuis node_modules au démarrage imposait d'embarquer lucide en
 * entier : 3548 fichiers et 27 Mo pour 23 icônes. lucide est donc désormais
 * une simple dépendance de développement.
 */
export function loadLucideIcons(): Record<string, string> {
  return ICON_PATHS;
}
