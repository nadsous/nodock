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
  <a href="https://marketplace.visualstudio.com/items?itemName=nadsite.nodock"><img src="https://img.shields.io/badge/VS%20Code%20Marketplace-nadsite.nodock-0098FF" alt="Sur le VS Code Marketplace"></a>
  <a href="https://open-vsx.org/extension/nadsite/nodock"><img src="https://img.shields.io/open-vsx/v/nadsite/nodock?label=Open%20VSX&color=a60ee5" alt="Sur Open VSX"></a>
</p>

<p align="center">
  <a href="https://open-vsx.org/extension/nadsite/nodock"><img src="https://img.shields.io/open-vsx/dt/nadsite/nodock?label=t%C3%A9l%C3%A9chargements&color=success" alt="Téléchargements"></a>
  <a href="https://open-vsx.org/extension/nadsite/nodock"><img src="https://img.shields.io/open-vsx/rating/nadsite/nodock?label=note" alt="Note"></a>
  <a href="https://github.com/nadsous/nodock/stargazers"><img src="https://img.shields.io/github/stars/nadsous/nodock?style=flat&color=yellow&logo=github" alt="Étoiles GitHub"></a>
  <a href="https://github.com/nadsous/nodock/issues"><img src="https://img.shields.io/github/issues/nadsous/nodock?color=orange&logo=github" alt="Issues"></a>
  <img src="https://img.shields.io/badge/licence-MIT-green" alt="Licence MIT">
</p>

---

Nodock analyse vos dépendances, détecte vos secrets exposés, scanne votre code et vous tient informé des dernières vulnérabilités — avec une interface qui suit le thème de votre IDE.

## 📥 Installation

### 🟦 VS Code

Panneau **Extensions** (`Ctrl+Shift+X`) → cherchez **Nodock** → **Installer**.

Ou depuis la palette (`Ctrl+P`) :

```
ext install nadsite.nodock
```

Ou en ligne de commande :

```bash
code --install-extension nadsite.nodock
```

### <img src="https://cdn.simpleicons.org/cursor/000000/FFFFFF" width="16" align="top"> Cursor

Cursor s'appuie sur [Open VSX](https://open-vsx.org/extension/nadsite/nodock), où Nodock est publié.

Panneau **Extensions** (`Ctrl+Shift+X`) → cherchez **Nodock** → **Installer**.

Ou en ligne de commande :

```bash
cursor --install-extension nadsite.nodock
```

> Pour vérifier : `cursor --list-extensions --show-versions | findstr nodock`

### <img src="https://cdn.simpleicons.org/windsurf/09B6A2" width="16" align="top"> Windsurf · <img src="https://cdn.simpleicons.org/vscodium/2F80ED" width="16" align="top"> VSCodium · <img src="https://cdn.simpleicons.org/gitpod/FFAE33" width="16" align="top"> Gitpod

Ces éditeurs utilisent également Open VSX : cherchez **Nodock** dans leur panneau Extensions, ou installez en ligne de commande.

```bash
windsurf --install-extension nadsite.nodock
codium   --install-extension nadsite.nodock
```

### 📦 Depuis un fichier `.vsix`

Pour une version précise ou une installation hors ligne : téléchargez le `.vsix` depuis les [releases GitHub](https://github.com/nadsous/nodock/releases), puis

```bash
cursor --install-extension nodock-0.7.8.vsix
```

Ou par l'interface : `Ctrl+Shift+P` → **Extensions: Install from VSIX…**

### 🛠 Depuis les sources

```bash
git clone https://github.com/nadsous/nodock.git
cd nodock
npm install
npm run compile
npx @vscode/vsce package    # produit nodock-X.Y.Z.vsix
```

`F5` lance directement un hôte de débogage avec l'extension chargée.

## 🚀 Démarrage

1. Ouvrez un projet
2. Cliquez sur l'icône **bouclier** dans la barre d'activité
3. **Scanner le projet**

Cliquez sur un résultat pour le déplier : vous y trouverez le chemin d'attaque, le correctif, et de quoi ouvrir le fichier concerné ou l'avis de sécurité.

Le premier scan interroge [OSV.dev](https://osv.dev) pour vos dépendances — aucune inscription ni clé API n'est requise. Rien n'est envoyé à un serveur tiers en dehors des noms et versions de paquets ; **votre code ne quitte jamais votre machine**.

> **Écosystèmes couverts** — Dépendances : npm, PyPI, Cargo, Go, Maven, RubyGems,
> Packagist (PHP), NuGet (.NET). Analyse de code et triage : JS/TS, Python, Go,
> Rust, Java/Kotlin, PHP, Ruby, C#. Et vos propres règles en **templates YAML**.

## ✨ Fonctionnalités

| Module | Description |
|---|---|
| 📦 **SCA** | npm, PyPI, Cargo, Go, Maven, RubyGems, **Packagist**, **NuGet** contre la base [OSV.dev](https://osv.dev) (gratuite, sans clé API). Lit les **lockfiles** (`package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`, `bun.lock`, `Cargo.lock`, `poetry.lock`, `uv.lock`, `Pipfile.lock`, `Gemfile.lock`, `composer.lock`, `packages.lock.json`) pour tester les versions réellement installées, avec score **CVSS** calculé et version corrigée. À défaut de lockfile, les manifestes (`package.json`, `requirements.txt`, `go.mod`, `pom.xml`, `build.gradle`, `Cargo.toml`) donnent une estimation marquée comme telle |
| 🔑 **Secrets** | 15 patterns : clés AWS, GitHub, OpenAI, Stripe, clés privées, JWT, connection strings… |
| 🐛 **SAST** | Règles statiques JS/TS/Python : `eval`, injection SQL/commandes, XSS, TLS désactivé, crypto faible… |
| 🧩 **Templates YAML** | **Créez vos propres règles de vulnérabilités en YAML** — déposées dans `.nodock/templates/`, chargées au scan. ~20 templates embarqués couvrent Go, Rust, Java/Kotlin, PHP, Ruby et C# (voir [Créer un template](#-créer-un-template)) |
| 🌐 **Websec** | Règles orientées chemin d'attaque : SSRF, open redirect, injection NoSQL, mass assignment, JWT `none`, CORS reflété, upload mal protégé… |
| 🏗️ **Infra / CI** | Dockerfile, docker-compose, GitHub Actions : conteneur root, image non épinglée, secrets en ENV, `pull_request_target`, permissions trop larges… |
| 🥷 **Vecteurs d'attaque** | Commandes dangereuses (shell, PowerShell, LOLBins) et risques supply-chain : scripts `postinstall`, dependency confusion, token de registre dans `.npmrc`… — chaque finding documente l'attaque 🥷 et la prévention 🛡️ |
| 🔭 **Audit de posture** | Ce qui MANQUE : routes sans vérification d'identité accédant à la base (Next.js, NestJS, Express, Fastify, Hono, **Django, Flask, FastAPI, Laravel, Spring**), entrées non validées, routes d'auth sans rate-limit, en-têtes de sécurité absents, `.env` ou clés privées versionnés |
| 📐 **Normes** | Patterns dépréciés selon les versions **réellement installées** (React 18/19, Next.js 13/14, Node, Python 3.12) avec correctifs et plan de migration agrégé |
| ⚖️ **Conformité** | Détecte trackers, cookies, collecte de données perso et indique **quoi déclarer dans chaque juridiction** : RGPD, UK GDPR, CCPA/CPRA, COPPA, HIPAA, PIPEDA/Loi 25, LGPD, PIPL, APPI, PDPA, DPDP, POPIA, Privacy Act |
| 📰 **Feed** | CVE récentes (API NVD) + flux RSS d'actualités sécurité configurables (The Hacker News, avis CISA par défaut) |
| 🎯 **Score** | Score de sécurité /100 **pondéré par le triage** (une faille « aucun chemin détecté » pèse moins qu'une exploitable), avec comparaison au scan précédent |
| 🔎 **Problèmes** | Les vulnérabilités sont soulignées dans l'éditeur et listées dans l'onglet **Problèmes** de VS Code |
| 🎯 **Triage** | Chaque alerte est confrontée au code : une faille n'est « exploitable » que si le projet atteint réellement l'API vulnérable citée par l'avis. Fonctionne pour JS/TS, Python, **Go, Rust, Java/Kotlin, PHP, Ruby et C#** |
| 🤫 **Baseline** | `.nodockignore` pour arbitrer une fois pour toutes les faux positifs |
| 📤 **Export** | Rapport en **JSON**, **SARIF** (compatible GitHub Code Scanning / CI) ou **CycloneDX** (SBOM : inventaire logiciel + vulnérabilités avec état d'analyse issu du triage) |

## ⌨️ Commandes

- `Nodock: Scanner le projet`
- `Nodock: Actualiser les actualités`
- `Nodock: Exporter le rapport (JSON/SARIF/CycloneDX)`
- `Nodock: Générer les mentions légales (RGPD)`

## 🧩 Créer un template

Un template décrit UNE règle de vulnérabilité en YAML. Déposez-le dans
`.nodock/templates/` à la racine du projet (chargé automatiquement) ou dans un
dossier listé par `nodock.templatePaths`. Un template qui reprend l'`id` d'un
template embarqué le remplace.

```yaml
id: NDK-GO-001
info:
  name: exec.Command avec chaîne
  severity: high            # critical | high | medium | low | info
  description: exec.Command exécute une commande — injection si la donnée vient de l'extérieur.
  remediation: Construisez les arguments en tableau, sans passer par un shell.
  reference: https://cwe.mitre.org/data/definitions/78.html
  tags: go, injection
files: '\.go$'              # regex de chemin, ou liste d'extensions : [go, mod]
matchers:
  - type: regex             # regex (pattern, flags optionnels) ou word (words)
    pattern: '\bexec\.Command\s*\('
  - type: word
    words: ['sh', '-c']
condition: or               # or (défaut) | and : combinaison des matchers
exempt: 'CommandContext'    # regex qui disculpe, fenêtre de ±2 lignes
multiline: false            # true = matcher appliqué au texte entier
```

Les templates héritent de tous les garde-fous : lignes de commentaire ignorées,
plafond anti-bruit par règle et par fichier, triage par emplacement
(tests/fixtures rétrogradés), baseline `.nodockignore`, diagnostics et exports.

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

## ⚙️ Configuration

| Paramètre | Défaut | Description |
|---|---|---|
| `nodock.rssFeeds` | The Hacker News, CISA | Flux RSS d'actualités |
| `nodock.templatePaths` | `[]` | Chemins additionnels de templates YAML (le dossier `.nodock/templates/` est chargé automatiquement) |
| `nodock.excludeFolders` | node_modules, .git, dist… | Dossiers exclus |
| `nodock.maxFileSizeKB` | 512 | Taille max des fichiers scannés |
| `nodock.maxFiles` | 5000 | Nombre max de fichiers par scan (au-delà : avertissement dans le rapport) |
| `nodock.showInProblems` | `true` | Souligner les vulnérabilités dans l'éditeur / onglet Problèmes |
| `nodock.downgradeUnreachable` | `true` | Rétrograder d'un cran les vulnérabilités sans chemin de code détecté |

## 🧑‍💻 Développement

```bash
npm install
npm run compile   # ou npm run watch
npm test          # tests unitaires hors ligne (parseurs, secrets, SAST, CVSS…)
npm run test:smoke # tests réseau réels (OSV/NVD/RSS) — nécessite Internet
# Puis F5 dans VS Code / Cursor pour lancer l'hôte de débogage
```

Le scan est annulable depuis la notification de progression. Une panne de l'API OSV
n'interrompt pas l'analyse des secrets, du code et de la conformité : le rapport
affiche un avertissement et le reste des résultats.

## 🗺 Roadmap

- [ ] App desktop (Tauri) Windows / Linux / macOS
- [ ] Intégration Semgrep pour un SAST plus profond (analyse syntaxique)
- [ ] Mode CLI headless pour la CI (`nodock scan --sarif`)
- [ ] Cache incrémental (ne re-scanner que les fichiers modifiés)
- [ ] Blocage pré-install de packages vulnérables
- [ ] Analyse des extensions/skills d'agents IA (type Rafter)
- [ ] Hooks pre-commit

> Swift/Package.swift n'est volontairement pas couvert par le SCA : la base OSV
> ne référence pas de manière fiable les bibliothèques Swift.

## 📄 Licence

MIT
