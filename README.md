# 🛡️ Nodock

**Scanner de vulnérabilités directement dans VS Code.** Nodock analyse vos dépendances, détecte vos secrets exposés, scanne votre code et vous tient informé des dernières vulnérabilités — avec une interface qui suit le thème de votre IDE.

## Fonctionnalités

| Module | Description |
|---|---|
| 📦 **SCA** | npm, PyPI, Cargo, Go, Maven, RubyGems contre la base [OSV.dev](https://osv.dev) (gratuite, sans clé API). Lit les **lockfiles** (`package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`, `Cargo.lock`, `poetry.lock`, `uv.lock`, `Gemfile.lock`) pour tester les versions réellement installées, avec score **CVSS** calculé et version corrigée |
| 🔑 **Secrets** | 15 patterns : clés AWS, GitHub, OpenAI, Stripe, clés privées, JWT, connection strings… |
| 🐛 **SAST** | Règles statiques JS/TS/Python : `eval`, injection SQL/commandes, XSS, TLS désactivé, crypto faible… |
| ⚖️ **Conformité** | Détecte trackers, cookies, collecte de données perso et indique **quoi déclarer dans chaque juridiction** : RGPD, UK GDPR, CCPA/CPRA, COPPA, HIPAA, PIPEDA/Loi 25, LGPD, PIPL, APPI, PDPA, DPDP, POPIA, Privacy Act |
| 📰 **Feed** | CVE récentes (API NVD) + flux RSS d'actualités sécurité configurables |
| 🎯 **Score** | Score de sécurité /100 avec anneau de progression animé |
| 🔎 **Problèmes** | Les vulnérabilités sont soulignées dans l'éditeur et listées dans l'onglet **Problèmes** de VS Code |
| 📤 **Export** | Rapport en **JSON** ou **SARIF** (compatible GitHub Code Scanning / CI) |

## Utilisation

1. Ouvrez un projet dans VS Code
2. Cliquez sur l'icône **Nodock** (bouclier) dans la barre d'activité
3. Cliquez sur **Scanner le projet**
4. Cliquez sur une vulnérabilité pour ouvrir le fichier / le lien de la CVE

## Commandes

- `Nodock: Scanner le projet`
- `Nodock: Actualiser les actualités`
- `Nodock: Exporter le rapport (JSON/SARIF)`
- `Nodock: Générer les mentions légales (RGPD)`

## ⚖️ Conformité mondiale / Mentions légales

Nodock détecte dans votre code les traitements soumis aux lois vie privée (Google Analytics, Meta Pixel,
cookies, localStorage, formulaires email, géolocalisation, caméra/micro, données santé, public enfant…)
et vous dit **précisément quoi mettre dans vos mentions légales pour chaque juridiction concernée** :

- 🇪🇺 RGPD + ePrivacy/CNIL · 🇬🇧 UK GDPR/PECR
- 🇺🇸 CCPA/CPRA (Do Not Sell/Share, GPC), COPPA, HIPAA
- 🇨🇦 PIPEDA + Loi 25 (Québec) · 🇧🇷 LGPD
- 🇨🇳 PIPL · 🇯🇵 APPI · 🇸🇬 PDPA · 🇮🇳 DPDP · 🇿🇦 POPIA · 🇦🇺 Privacy Act

La commande `Nodock: Générer les mentions légales (RGPD, CCPA…)` crée un fichier
`mentions-legales.md` **multijuridictions** pré-rempli à la racine du projet.

> ⚠️ Modèle fourni à titre indicatif — pas un conseil juridique.

## Configuration

| Paramètre | Défaut | Description |
|---|---|---|
| `nodock.rssFeeds` | The Hacker News | Flux RSS d'actualités |
| `nodock.excludeFolders` | node_modules, .git, dist… | Dossiers exclus |
| `nodock.maxFileSizeKB` | 512 | Taille max des fichiers scannés |
| `nodock.maxFiles` | 5000 | Nombre max de fichiers par scan (au-delà : avertissement dans le rapport) |
| `nodock.showInProblems` | `true` | Souligner les vulnérabilités dans l'éditeur / onglet Problèmes |

## Développement

```bash
npm install
npm run compile   # ou npm run watch
npm test          # tests unitaires hors ligne (parseurs, secrets, SAST, CVSS)
# Puis F5 dans VS Code / Cursor pour lancer l'hôte de débogage
```

Le scan est annulable depuis la notification de progression. Une panne de l'API OSV
n'interrompt pas l'analyse des secrets, du code et de la conformité : le rapport
affiche un avertissement et le reste des résultats.

## Roadmap

- [ ] App desktop (Tauri) Windows / Linux / macOS
- [ ] Intégration Semgrep pour un SAST plus profond
- [ ] Blocage pré-install de packages vulnérables
- [ ] Analyse des extensions/skills d'agents IA (type Rafter)
- [ ] Hooks pre-commit

## Licence

MIT
