# 🛡️ Nodock — Release Notes

## [Unreleased] — 2026-08-05

### ✨ Nouveau module : Vecteurs d'attaque (`kind: 'attack'`)

Nodock raisonne désormais **comme un hacker qui cible votre projet**. Chaque règle documente le scénario d'attaque (🥷) ET la prévention (🛡️).

**Commandes dangereuses** (scripts shell, PowerShell, et instructions piégées dans la documentation) :

| Règle | Détecte | Sévérité |
|---|---|---|
| `ATK-CMD-001` | `curl \| bash` / `wget \| sh` — exécution de code distant | Critique |
| `ATK-CMD-002` | Payload base64 pipé dans un shell (obfuscation) | Élevée |
| `ATK-CMD-003` | `eval $(curl …)` — eval sur contenu distant | Critique |
| `ATK-CMD-004` | Reverse shells (`/dev/tcp`, `nc -e`, `ncat -e`, mkfifo) | Critique |
| `ATK-CMD-005` | Exfiltration de secrets (upload de `.env`, `id_rsa`, `.npmrc` + domaines webhook.site, requestbin, oastify…) | Critique |
| `ATK-CMD-006` | Commandes destructives (`rm -rf /`, `dd of=/dev/sd*`, `mkfs`, fork bomb) | Critique |
| `ATK-CMD-007` | `chmod 777` récursif | Moyenne |
| `ATK-CMD-008` | PowerShell encodé (`-enc`), `IEX`, `DownloadString` (fileless malware) | Élevée |
| `ATK-CMD-009` | LOLBins Windows (`certutil -urlcache`, `bitsadmin`, `mshta http`, `rundll32 javascript`) | Élevée |

> Dans les fichiers Markdown, seules les règles à fort signal s'appliquent — un README qui impose `curl | bash` est un vrai vecteur d'ingénierie sociale.

**Supply chain par écosystème** :

| Règle | Écosystème | Détecte | Sévérité |
|---|---|---|---|
| `ATK-NPM-001` | npm | Scripts `pre/postinstall` (exécution auto à l'install) | Moyenne |
| `ATK-NPM-002` | npm | Script d'install avec réseau/shell (`curl`, `node -e`, base64) | Critique |
| `ATK-NPM-003` | npm | Dépendance `git+http://`, `.tgz` HTTP, `file:../` | Élevée |
| `ATK-NPM-004` | npm | Registry en HTTP clair (`.npmrc`) | Élevée |
| `ATK-NPM-005` | npm | `_authToken` commité dans `.npmrc` | Critique |
| `ATK-PY-001` | Python | Dépendance `git+http://` dans requirements | Élevée |
| `ATK-PY-002` | Python | `--extra-index-url` → **dependency confusion** | Élevée |
| `ATK-PY-003` | Python | Code exécuté dans `setup.py` à l'install | Élevée |
| `ATK-MK-001` | Make | Téléchargement exécuté par le Makefile | Élevée |
| `ATK-RS-001` | Rust | Réseau/`Command::new` dans `build.rs` | Élevée |
| `ATK-RB-001` | Ruby | Gem depuis `git: http://` | Élevée |
| `ATK-PHP-001` | PHP | Scripts composer avec shell/PHP arbitraire | Élevée |
| `ATK-GIT-001` | git | `.gitignore` qui n'exclut **pas** `.env` | Critique |

**Non-doublon assumé** : Docker, docker-compose et GitHub Actions restent couverts par le module `infra` ; les vulnérabilités applicatives par `websec`/`sast`.

### 🔧 Intégration

- `types.ts` : nouveau kind `'attack'` dans l'union `Finding.kind`
- `scanner.ts` : `ATTACK_FILE_TYPES` + `scanAttackInText()` branchés sur le passage unique (aucune lecture de fichier supplémentaire)
- `webview.ts` : groupe **🥷 Vecteurs d'attaque** affiché entre Code (SAST) et Normes de codage
- Bénéficie automatiquement du plafond anti-bruit (5 occurrences/règle/fichier), du triage, de la baseline `.nodockignore`, des diagnostics VS Code et de l'export SARIF

### ✅ Tests

- Nouveau : `test/attack.test.cjs` — 16 cas (chaque règle a un cas vulnérable **et** un cas sain, plus le format 🥷/🛡️ des findings)

### 📁 Fichiers modifiés

```
src/attack.ts          (nouveau — 13 règles + 9 commandes dangereuses)
src/types.ts           (+1 kind)
src/scanner.ts         (+3 lignes d'intégration)
src/webview.ts         (label + ordre d'affichage)
test/attack.test.cjs   (nouveau)
```

---

## Rappel de la session (versions précédentes)

- **SCA multi-écosystèmes** : npm, PyPI, Cargo, Go, Maven, RubyGems via OSV.dev
- **Secrets** : 15 patterns (AWS, GitHub, OpenAI, Stripe, clés privées, JWT…) avec masquage
- **SAST** : ~20 règles JS/TS/Python
- **Conformité mondiale** : RGPD, UK GDPR, CCPA/CPRA, COPPA, HIPAA, PIPEDA/Loi 25, LGPD, PIPL, APPI, PDPA, DPDP, POPIA, Privacy Act + générateur `mentions-legales.md` multijuridictions
- **Feed** : CVE 7 derniers jours (NVD) + RSS configurables
- **Export** : JSON + SARIF (GitHub Code Scanning)
