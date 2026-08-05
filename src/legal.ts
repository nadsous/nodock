import * as vscode from 'vscode';

/** Génère un fichier mentions-legales.md multijuridictions pré-rempli. */
export async function generateLegalNotice(): Promise<void> {
  const folder = vscode.workspace.workspaceFolders?.[0];
  if (!folder) {
    vscode.window.showErrorMessage('Ouvrez d\'abord un dossier dans VS Code.');
    return;
  }
  const uri = vscode.Uri.joinPath(folder.uri, 'mentions-legales.md');
  const content = `# Mentions légales & Politique de confidentialité internationale

> Généré par **Nodock** — modèle multijuridictions à compléter et faire valider par un professionnel du droit.
> Ceci est un modèle, pas un conseil juridique.

## 1. Éditeur du site

- Nom / Dénomination sociale : *[À compléter]*
- Forme juridique & capital : *[À compléter]*
- Siège social : *[À compléter]*
- RCS / SIRET : *[À compléter]*
- Directeur de la publication : *[À compléter]*
- Contact : *[email / téléphone]*

## 2. Hébergeur

- Nom / adresse / téléphone : *[À compléter]*

## 3. Données collectées & finalités

| Donnée | Finalité | Base légale | Durée | Destinataires |
|---|---|---|---|---|
| *[ex : email]* | *[newsletter]* | *[consentement]* | *[3 ans]* | *[Mailchimp (USA)]* |

## 4. 🇪🇺 Union européenne — RGPD

- DPO / contact vie privée : *[À compléter]*
- Droits : accès, rectification, effacement, portabilité, opposition → exercice via *[email]*
- Réclamation : CNIL (www.cnil.fr) ou autorité locale
- Transferts hors UE : *[pays + garanties : CCT, EU-US Data Privacy Framework]*
- Breach notification : nous nous engageons à notifier sous 72h

## 5. 🇬🇧 Royaume-Uni — UK GDPR / PECR

- UK Representative : *[si applicable]*
- Consentement cookies : bannière conforme PECR

## 6. 🇺🇸 Californie — CCPA/CPRA

- **Notice at Collection** : catégories de données collectées et finalités listées au point 3
- 🔗 **[Do Not Sell or Share My Personal Information](#)** ← LIEN OBLIGATOIRE si trackers/ads
- Nous respectons le signal **Global Privacy Control (GPC)**
- Données sensibles : *[géolocalisation ? biométrie ?]* → droit de limitation
- Non-discrimination : aucun prix/service différencié en cas d'exercice de vos droits

## 7. 🇺🇸 Enfants — COPPA

- [ ] Ce service ne cible PAS les moins de 13 ans / [ ] Consentement parental vérifiable en place : *[décrire]*

## 8. 🇨🇦 Canada — PIPEDA & Loi 25 (Québec)

- Agent de protection des renseignements personnels : *[À compléter]*
- Confidentialité par défaut : activée
- Registre des incidents de confidentialité : maintenu

## 9. 🇧🇷 Brésil — LGPD

- Encarregado (DPO) : *[À compléter]*
- Droits : confirmação, acesso, correção, eliminação, portabilidade, revogação do consentimento

## 10. 🌏 Autres juridictions

- 🇨🇳 PIPL : consentement séparé pour transferts/sensibles — *[si utilisateurs chinois]*
- 🇯🇵 APPI : finalité d'utilisation publiée — *[si utilisateurs japonais]*
- 🇸🇬 PDPA : DPO désigné — *[si utilisateurs singapouriens]*
- 🇮🇳 DPDP : notice en langues locales — *[si utilisateurs indiens]*
- 🇿🇦 POPIA : Information Officer — *[si utilisateurs sud-africains]*
- 🇦🇺 Privacy Act : APP Privacy Policy — *[si utilisateurs australiens]*

## 11. Cookies

| Cookie/Tech | Finalité | Durée | Tiers |
|---|---|---|---|
| *[ex : _ga]* | *[audience]* | *[13 mois]* | *[Google]* |

Bandeau de consentement **avant dépôt** (UE/UK) · Refus aussi simple que l'acceptation ·
Opt-out permanent disponible (USA).

*Dernière mise à jour : ${new Date().toISOString().slice(0, 10)}*
`;
  await vscode.workspace.fs.writeFile(uri, Buffer.from(content, 'utf8'));
  const doc = await vscode.workspace.openTextDocument(uri);
  await vscode.window.showTextDocument(doc);
  vscode.window.showInformationMessage(
    'Nodock : mentions-legales.md (multijuridictions) généré — complétez les sections [À compléter].'
  );
}
