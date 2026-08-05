<p align="center">
  <img src="media/nodock.svg" alt="Nodock" width="200">
</p>

<h1 align="center">Nodock</h1>

<p align="center">
  <strong>Scanner de vulnérabilités directement dans VS Code.</strong><br>
  Dépendances, secrets, code et conformité — avec un triage qui vérifie
  si la faille concerne <em>vraiment</em> votre projet.
</p>

<p align="center">
  <img src="https://img.shields.io/badge/VS%20Code-%5E1.90.0-0098FF" alt="VS Code ^1.90.0">
  <img src="https://img.shields.io/badge/licence-MIT-green" alt="Licence MIT">
  <img src="https://img.shields.io/badge/d%C3%A9pendances-0-brightgreen" alt="Zéro dépendance runtime">
</p>

---

Nodock analyse vos dépendances, détecte vos secrets exposés, scanne votre code et vous tient informé des dernières vulnérabilités — avec une interface qui suit le thème de votre IDE.

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
| 🎯 **Triage** | Chaque alerte est confrontée au code : une faille n'est « exploitable » que si le projet atteint réellement l'API vulnérable citée par l'avis |
| 🤫 **Baseline** | `.nodockignore` pour arbitrer une fois pour toutes les faux positifs |
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

## 🎯 Triage : est-ce que ça me concerne ?

Un scanner qui compare des numéros de version signale des failles qu'aucun chemin
de code n'atteint. Nodock lit les API citées par l'avis de sécurité (entre
backticks : `oidcProvider()`, `pkg/plugins/mcp`…) et vérifie si votre code les
utilise réellement.

| Verdict | Signification |
|---|---|
| **Exploitable** | Le paquet est importé **et** l'API vulnérable apparaît dans le code |
| **À vérifier** | Importé, mais l'avis ne nomme aucune API précise |
| **Aucun chemin détecté** | Paquet jamais importé, ou importé sans trace de l'API vulnérable |

> « Aucun chemin détecté » ne veut **pas** dire « non vulnérable ». Un usage hors
> code applicatif (build, CLI) reste invisible à cette analyse, et un futur usage
> réintroduirait la faille. Rien n'est masqué : ces findings sont seulement
> rétrogradés d'un cran et classés en fin de liste.

Les secrets et les motifs de code sont triés de la même façon, par emplacement :
un secret dans `tests/fixtures/` ou `.env.example` n'a pas la portée du même
secret en production.

## 🤫 `.nodockignore`

Pour arbitrer un faux positif une fois pour toutes, à la racine du projet :

```gitignore
# un chemin
src/vendor/**

# une règle, partout
CMP-009

# une règle, sur un chemin précis
NDK-JS-001 src/rules/**

# une vulnérabilité précise
CVE-2026-53512
```

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
