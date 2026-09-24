# Identité TPM des appareils

La présence du code dans le dépôt ne signifie pas qu'un serveur ou un miroir de binaires a été mis à jour.

## Garanties et limites

L'identité repose sur une clé ECDSA P-256 créée dans le TPM, et non sur une adresse MAC ou un numéro de série envoyé par le client. Le serveur vérifie les attributs TPM `fixedTPM`, `fixedParent`, `sensitiveDataOrigin`, `restricted`, `sign`, l'absence de `decrypt` et le nom SHA-256. Une activation de justificatif (`MakeCredential`/`ActivateCredential`) lie cette clé à une clé d'endossement EK dont le certificat remonte à une autorité explicitement approuvée.

La clé d'attestation restreinte (AK) sert directement à signer les requêtes du protocole MySync. Le TPM hache le message avec `TPM2_Hash`, produit le ticket de validation puis signe avec `TPM2_Sign`. Il n'y a pas de seconde clé applicative ni de clé privée logicielle de secours.

La création, le chargement et l'activation de la clé utilisent des sessions TPM chiffrées, salées avec l'EK, qui authentifient aussi les réponses du TPM. Cela évite les sessions de politique sans secret partagé, ainsi que le chemin de déchiffrement incompatible observé avec tpm2-tss 4.2 sur Arch. Le test de création puis rechargement s'exécute sur les deux distributions en CI; aucune ancienne bibliothèque système n'est imposée comme contournement.

Le blob privé enregistré dans la configuration est enveloppé par le TPM : le copier avec toute la configuration sur un autre TPM ne permet pas de signer. En revanche :

- Un processus ayant accès à la configuration et au TPM sur la machine légitime peut utiliser la clé. Ce mécanisme ne prouve pas que le système d'exploitation est sain, et ne remplace pas le cloisonnement local, les mises à jour de sécurité ou le chiffrement du disque.
- La qualité de la liaison matérielle dépend du TPM et des autorités EK sélectionnées. Une autorité de test ou une autorité délivrant des certificats pour des TPM clonables ne convient pas à une politique « matériel non exportable ».
- Aucun contrôle PCR/Secure Boot, aucune attestation distante de l'état du système, ni vérification automatique OCSP/CRL n'est effectué. La chaîne, la période de validité, l'usage EK `2.23.133.8.1` et l'usage de la clé sont vérifiés lors de l'appairage. Une modification du magasin de confiance ne révoque pas les appareils déjà approuvés : utiliser la révocation explicite.
- Le serveur conserve l'empreinte de la clé EK, un identifiant potentiellement corrélable de l'appareil. Il ne collecte pas de numéros de disque ni de `machine-id`.
- HTTPS reste indispensable. Les réponses et les fichiers ne sont pas chiffrés de bout en bout; un proxy TLS tel que Cloudflare peut les lire. Le protocole ne protège pas d'un serveur compromis.

## Prérequis client

Debian 13 ou Arch Linux/dérivées, TPM 2.0 accessible via `/dev/tpmrm0`, EK RSA-2048 ou ECC P-256 et certificat EK constructeur. Le certificat est lu dans les index NV standards du TPM, ou fourni explicitement en DER via `--ek-cert` lorsqu'il en est absent. Sans certificat constructeur correspondant à l'EK de ce TPM, l'appairage est refusé. Ne pas contourner ce refus par un certificat auto-signé.

```sh
./deploy/install-tpm-deps.sh
```

Le script installe les paquets de la distribution, sans remplacer les bibliothèques système à la main. Il peut ajouter l'utilisateur au groupe `tss`; redémarrer ensuite pour renouveler les groupes du service utilisateur. Ne pas rendre le périphérique TPM accessible en écriture à tout le monde. Le client fonctionne sans root et sans accès au TPM dans le conteneur serveur.

L'installateur distribué par le serveur effectue aussi un contrôle local avec `mysync doctor` avant de poser le client. Cette commande vérifie l'accès au TPM et que le certificat EK correspond à sa clé. Pour un certificat externe, définir `MYSYNC_EK_CERT=/chemin/ek.der` lors de l'installation. `doctor` ne vérifie **pas** la chaîne de confiance du fabricant : celle-ci reste vérifiée pendant l'appairage contre les autorités configurées sur le serveur.

Les hiérarchies TPM utilisées doivent être accessibles avec leur autorisation vide par défaut; les mots de passe de hiérarchie personnalisés ne sont pas pris en charge. Ne pas effacer un TPM pour contourner cette limitation : il peut contenir d'autres clés, notamment celles utilisées pour déverrouiller des disques.

Si les certificats intermédiaires EK ne sont pas présents dans le certificat stocké en NV ou fourni en DER, les fournir depuis une source constructeur vérifiée avec `mysync enroll --ek-chain /chemin/intermediaires.pem ...`. Le client n'effectue aucun téléchargement AIA implicite et le serveur n'utilise pas le magasin CA web du système.

### Certificat EK absent du TPM

Certains fTPM AMD ne possèdent pas les index NV EK standards. Sur une machine de confiance, `tpm2-tools` peut demander le certificat au service du fabricant à partir de la clé EK publique. Cette requête divulgue au fabricant un identifiant potentiellement corrélable de l'appareil. Vérifier la provenance du certificat et conserver la validation TLS ; **ne pas** utiliser `tpm2_getekcertificate -X`, qui désactive cette validation.

```sh
ek_workdir=$(mktemp -d)
sudo tpm2_createek -G rsa -u "$ek_workdir/ek.pub" -c "$ek_workdir/ek.ctx"
sudo tpm2_getekcertificate -u "$ek_workdir/ek.pub" -o "$ek_workdir/ek.der"
install -d -m 0700 "$HOME/.config/mysync"
sudo chmod 0644 "$ek_workdir/ek.der"
install -m 0600 "$ek_workdir/ek.der" "$HOME/.config/mysync/ek.der"
mysync doctor --ek-cert "$HOME/.config/mysync/ek.der"
```

Ces commandes ne modifient pas les index NV. `ek.der` doit être lisible par l'utilisateur qui lance le client et gardé hors du dossier synchronisé. Utiliser `MYSYNC_EK_CERT="$HOME/.config/mysync/ek.der"` pour l'installateur et `mysync enroll --ek-cert "$HOME/.config/mysync/ek.der" ...` pour l'appairage. Un fichier extérieur n'est jamais ajouté automatiquement aux autorités de confiance : le serveur exige toujours une chaîne vers une racine EK approuvée et une activation par ce TPM.

## Configuration du serveur

Obtenir et vérifier hors bande les certificats racines EK des fabricants acceptés. Constituer un fichier PEM contenant uniquement ces autorités de confiance. Aucune racine de test et aucune liste de constructeurs non vérifiée ne sont préinstallées par le projet.

```sh
docker compose -f deploy/compose.yaml run --rm \
  -v /chemin/absolu/ek-roots.pem:/trust/ek-roots.pem:ro \
  server device auth-configure --data-dir /data \
  --public-url https://sync.example.org --ek-roots /trust/ek-roots.pem
```

Cette commande enregistre l'origine et les racines dans SQLite; le montage PEM n'est requis que pour la configuration. `--public-url` doit être l'origine exacte utilisée par les clients, sans sous-chemin. Le proxy doit conserver la méthode, le chemin, la chaîne de requête, le corps et les en-têtes `Authorization`/`x-mysync-proof`. L'origine n'est jamais déduite d'en-têtes `Forwarded` fournis par le client. Ne pas mettre en cache les API authentifiées ni leur appliquer des transformations. Les redirections ne sont pas suivies.

Le serveur accepte uniquement les identités TPM approuvées. Il n'a pas besoin de matériel TPM : l'image inclut `tpm2_makecredential` pour effectuer le calcul côté serveur. La production tourne sans root, avec `/tmp` privé en mémoire pour les défis temporaires.

## Appairage et approbation

1. L'administrateur crée une invitation avec `device invite --name NOM --output FICHIER`. Elle contient 256 bits aléatoires, n'est stockée que sous forme de hash en base et expire après 15 minutes. Utiliser un nom distinct par appareil et transmettre le fichier de manière confidentielle.
2. Le client lance `mysync enroll --server URL --dir DOSSIER --invitation-stdin < FICHIER`. Il conserve sa clé et le défi dans `config.enrollment.json` privé, hors du miroir. Une nouvelle tentative reprend la même clé au lieu de consommer l'invitation avec une nouvelle identité.
3. Le serveur vérifie le certificat EK, réserve l'invitation à une seule clé puis vérifie la réponse d'activation. L'appareil reste sans accès aux fichiers pendant l'attente d'approbation (24 heures maximum).
4. L'administrateur exécute `device pending`, compare l'empreinte affichée avec celle du client par un canal fiable, puis `device approve --id ID --fingerprint EMPREINTE`. Une empreinte fournie uniquement par le serveur ne suffit pas pour cette comparaison.
5. Le client exécute `mysync enroll-activate`. Il vérifie l'accès approuvé, remplace sa configuration privée, efface le fichier d'appairage en attente et synchronise. Si `/install.sh` a été utilisé, activer ensuite le service avec `systemctl --user enable --now mysync.service` et le démarrage sans session avec `sudo loginctl enable-linger "$(id -un)"`. Pour une construction depuis les sources, utiliser `./deploy/install-client.sh`.

Les commandes administrateur nécessitent aussi `--data-dir /data` dans le conteneur. Elles sont locales au serveur : aucune route HTTP d'approbation n'est exposée. Une invitation volée peut bloquer l'appairage en se réservant une clé, mais elle ne suffit pas à obtenir l'accès sans attestation et approbation de l'empreinte attendue.

## Révocation et récupération

`device revoke --name NOM --data-dir /data` désactive l'appareil et supprime ses sessions. Toute nouvelle authentification est rejetée; une opération déjà autorisée peut se terminer.

Une invitation perdue, réservée par la mauvaise clé ou expirée peut être annulée avec `device cancel --id ID --data-dir /data`. Cette commande ne peut pas annuler une identité approuvée. Conserver à part le fichier local `config.enrollment.json` annulé (hors miroir, permissions privées), puis créer une nouvelle invitation avant de relancer l'appairage. Les invitations expirées n'empêchent pas d'en créer une nouvelle.

Après remplacement/effacement du TPM ou perte définitive de la configuration : révoquer l'ancien appareil, conserver la configuration et son état local en sauvegarde privée, puis créer un nouvel appareil sous un nouveau nom. Ne pas réutiliser une configuration associée à un autre TPM. Faire une sauvegarde du miroir avant la nouvelle synchronisation. Aucun mécanisme de récupération ne transforme le blob TPM en clé logicielle.

## Protocole des requêtes

Le protocole MySync est un profil de preuve de possession propre au projet, **pas** une implémentation OAuth/DPoP compatible RFC 9449.

Chaque preuve signe `mysync/request/v1\n` suivi de la sérialisation JSON de `Claims` : version, identifiant d'appairage, nonce aléatoire de 256 bits, horodatage, méthode HTTP, SHA-256 de l'URL externe complète (query comprise), SHA-256 du corps brut et SHA-256 du jeton de session. La signature ECDSA P-256 utilise SHA-256. L'enveloppe JSON contient la signature brute `r || s` de 64 octets en hexadécimal et est encodée en base64url dans `x-mysync-proof`.

Une requête signée à `POST /v1/auth/session` obtient une session de 15 minutes. Les autres requêtes utilisent `Authorization: MySync JETON` et une nouvelle preuve liée à ce jeton; le jeton seul est inutilisable. Le client renouvelle automatiquement la session. Les sessions et invitations sont stockées hachées côté serveur, pas les secrets en clair.

Le serveur accepte un horodatage compris entre 60 secondes dans le passé et 30 secondes dans le futur. Il conserve chaque nonce utilisé 120 secondes dans une table SQLite partagée, y compris entre redémarrages. Les horloges doivent être synchronisées. Les transferts utilisent des blocs d'au plus 8 Mio; les modifications de corps, query, méthode, jeton ou destination invalident la preuve. Les attributs de clé et le statut de révocation sont vérifiés pour les requêtes authentifiées.

La signature, la session, la fraîcheur et le rejeu sont contrôlés avant de lire le corps. Le nonce est alors réservé, même si le transfert échoue : une nouvelle tentative exige une nouvelle preuve. Au plus huit requêtes signées sont admises simultanément, avec 30 secondes pour lire chaque corps. Le SHA-256 du corps et la validité de la session/appairage sont revérifiés avant le traitement. Les tests couvrent aussi les corps inachevés, la saturation de cette limite et une révocation pendant un transfert.

## Tests et validation

```sh
docker build -t mysyncfiles-tpm-dev -f deploy/Dockerfile.tpm-dev .
docker run --rm --user "$(id -u):$(id -g)" \
  --mount type=bind,src="$PWD",dst=/src \
  -e CARGO_HOME=/src/target/docker-cargo \
  -e CARGO_TARGET_DIR=/src/target/docker-tpm \
  mysyncfiles-tpm-dev cargo +1.98.1 test --locked
```

Les tests créent des TPM simulés isolés et des autorités éphémères. Ils couvrent les EK RSA/ECC, certificats non fiables/expirés/mauvais usage, activation avec une mauvaise clé, copie du blob sur un autre TPM, approbation, reprise d'appairage, expiration, rejeu, altération de requêtes, sessions volées, révocation et transferts signés par blocs. Les régressions de synchronisation et les mises à jour signées sont aussi testées.

`deploy/Dockerfile.tpm-runtime` fournit les environnements d'exécution Debian 13 et Arch pour rejouer le même binaire de test avec leurs bibliothèques natives, sans root. La CI vérifie ces échanges complets, pas uniquement `mysync --version`.

Ces tests ne constituent ni un audit indépendant ni une validation sur TPM physique. Avant un déploiement critique, vérifier sur chaque famille matérielle le certificat constructeur réel, les droits `/dev/tpmrm0`, l'appairage, la synchronisation après redémarrage et la récupération après révocation. Aucun certificat ni secret de test ne doit être ajouté à la confiance de production.
