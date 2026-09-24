# MySyncFiles

MySyncFiles synchronise un dossier local entre des machines Linux à travers un serveur HTTPS. Chaque dossier local est un miroir complet du serveur. Le serveur arbitre les modifications concurrentes : lorsqu'une version locale perd un conflit, elle est conservée dans `.mysync-conflicts/` avant que la version du serveur soit appliquée.

Le client fonctionne en continu : il surveille les fichiers, interroge le serveur toutes les 15 secondes et réessaie après une coupure réseau. Un service systemd utilisateur peut le lancer dès le démarrage de la machine, même sans session ouverte. Il vérifie aussi les nouvelles versions du programme au démarrage puis toutes les six heures. Les mises à jour sont signées Ed25519 et contrôlées par SHA-256 avant installation atomique.

Le même code client fonctionne sur Debian 13, Arch Linux et ses dérivées, notamment CachyOS. Aucune variante de code par distribution n'est nécessaire. Le système de versions prend en charge Linux x86-64 et AArch64 ; chaque architecture exige son propre artefact signé.

À partir de la version 0.3.0, les nouvelles installations exigent un TPM 2.0 côté client, un certificat constructeur EK vérifiable et une approbation administrateur. Une invitation sert uniquement à l'appairage : l'accès aux fichiers exige ensuite une signature TPM par requête. Aucun identifiant matériel déclaratif (MAC, numéro de disque, `machine-id`) n'est utilisé comme preuve d'identité. Voir le [protocole, les prérequis et la migration](docs/device-auth.md).

## Construire

Utiliser la version Rust fixée dans `rust-toolchain.toml` (via [rustup](https://rustup.rs/), dans l'espace utilisateur, sans `sudo cargo`). Installer les dépendances de compilation et de test :

```sh
# Debian 13
sudo apt install build-essential pkg-config libssl-dev libtss2-dev tpm2-tools swtpm swtpm-tools
# Arch Linux et dérivées
sudo pacman -S --needed base-devel pkgconf openssl tpm2-tss tpm2-tools swtpm
```

Puis, depuis le dépôt :

```sh
cargo build --release --locked
cargo test --locked
```

Les binaires produits sont `target/release/mysync` (client), `target/release/mysync-server` (serveur) et `target/release/mysync-release` (publication signée). Construire depuis le code source est la méthode de démarrage recommandée : les mises à jour suivantes seront vérifiées avec la clé publique intégrée dans le client.

Pour compiler et tester sans installer la chaîne de compilation sur l'hôte, utiliser [l'environnement Docker de développement](docs/device-auth.md#tests-et-validation). Les tests TPM utilisent un simulateur et une autorité éphémère, sans modifier un TPM physique.

## Serveur

Le serveur est fourni sous [Docker Compose](deploy/compose.yaml). Le conteneur tourne sans root, sans capacités Linux, avec un système de fichiers en lecture seule. Il n'expose son port que sur `127.0.0.1:8484`; un proxy HTTPS tel que Nginx doit être placé devant. Le [fichier Nginx](deploy/nginx-sync.conf) est un exemple à adapter au domaine choisi. Un proxy Cloudflare peut rester activé : les gros fichiers sont envoyés par blocs reprenables de 8 Mio pour rester sous sa [limite de taille par requête](https://developers.cloudflare.com/support/troubleshooting/http-status-codes/4xx-client-error/error-413/).

Créer deux répertoires distincts sur l'hôte : un répertoire privé pour les fichiers et la base SQLite (mode `0700`), un répertoire en lecture pour les versions du client. Copier `deploy/.env.example` vers `deploy/.env`, puis y définir les chemins absolus et l'UID/GID du compte propriétaire. `deploy/.env` est ignoré par Git. Démarrer le serveur :

```sh
docker compose -f deploy/compose.yaml build
docker compose -f deploy/compose.yaml up -d
curl -fsS http://127.0.0.1:8484/v1/health
```

Ne pas lancer deux processus serveur sur la même base SQLite. Les données persistent hors du conteneur. Le volume des versions est monté en lecture seule et ne contient **jamais** la clé de signature privée.

Configurer d'abord l'origine HTTPS et les autorités EK constructeur de confiance, suivant le [guide d'appairage](docs/device-auth.md#configuration-du-serveur). Le serveur lui-même n'a pas besoin de TPM. Il utilise `tpm2-tools`, inclus dans son image Docker, pour produire les défis d'attestation.

Créer une invitation différente par appareil. L'option `--output` l'enregistre avec le mode `0600` sans l'afficher; sa validité est de 15 minutes :

```sh
install -d -m 700 "$HOME/.local/share/mysync-keys"
docker compose -f deploy/compose.yaml run --rm -v "$HOME/.local/share/mysync-keys:/keys" server device invite --data-dir /data --name nouvel-appareil --output /keys/nouvel-appareil.key
docker compose -f deploy/compose.yaml run --rm server device pending --data-dir /data
```

Un appareil révoqué ne peut plus authentifier de nouvelles requêtes : `docker compose -f deploy/compose.yaml run --rm server device revoke --data-dir /data --name nouvel-appareil`. Ses sessions sont supprimées. Une requête déjà autorisée peut finir son traitement.

## Installer un miroir local

L'URL du serveur est configurable. Dans les commandes ci-dessous, remplacer `https://sync.example.org` par l'origine HTTPS de son serveur. Elles nécessitent un serveur et un client 0.3.0 ou plus récents, configurés pour le TPM. Installer d'abord les bibliothèques natives (un redémarrage peut être nécessaire pour les droits d'accès au TPM) :

```sh
./deploy/install-tpm-deps.sh
./target/release/mysync enroll --server https://sync.example.org --dir "$HOME/Sync" --invitation-stdin < /chemin/prive/invitation
```

Le client affiche l'identifiant d'appairage et l'empreinte de sa clé TPM. Comparer cette empreinte avec celle du serveur par un canal fiable, puis faire approuver l'appareil par l'administrateur :

```sh
docker compose -f deploy/compose.yaml run --rm server device approve --data-dir /data --id ID_APPARIAGE --fingerprint EMPREINTE_CLIENT
```

Sur le client, terminer ensuite l'appairage :

```sh
./target/release/mysync enroll-activate
```

La même procédure convient au premier appareil et aux suivants. L'activation lance une synchronisation bidirectionnelle; sauvegarder les fichiers importants avant la première synchronisation. Le fichier `~/.config/mysync/config.json` contient le blob privé enveloppé par le TPM, pas une clé privée exportable. Il reste privé (`0600`) et doit être conservé hors du dossier synchronisé. Ne transmettre ni invitation ni secret en argument de commande. Les anciennes commandes `init`/`connect` sont réservées à la migration avec authentification historique explicitement autorisée.

Installer ensuite le client et son service de fond :

```sh
./deploy/install-client.sh
systemctl --user status mysync.service
```

Le script installe le binaire dans `~/.local/bin`, active `mysync.service` et active le *linger* systemd (via `sudo` si nécessaire). Le linger démarre le gestionnaire de services utilisateur au boot et le maintient après déconnexion. Le service redémarre le client s'il s'arrête, y compris après une mise à jour du programme. Consultez ses journaux avec `journalctl --user -u mysync.service -f`.

Le dossier `~/Sync` reste un dossier local ordinaire : on peut l'ajouter aux favoris de Dolphin ou d'un autre gestionnaire de fichiers. Les commandes `mysync sync`, `mysync status` et `mysync update` permettent de déclencher ou vérifier manuellement une synchronisation ou une mise à jour.

## Versions et mises à jour du client

Le serveur publie, pour chaque architecture, un manifeste signé (`/v1/updates/<cible>/latest.json` et `latest.sig`) et un binaire versionné. Le client n'accepte qu'une version SemVer plus récente, destinée à son architecture, signée par la clé publique de [`src/update_public_key.hex`](src/update_public_key.hex), et dont la taille et l'empreinte SHA-256 correspondent au manifeste. Une version invalide n'est pas installée. La clé privée ne doit pas être publiée ni montée dans le conteneur; elle doit idéalement être conservée hors ligne. La présence du code 0.3.0 dans ce dépôt ne signifie pas qu'un artefact signé a été publié. Pour publier une version officielle :

```sh
mysync-release publish --secret-key /chemin/prive/cle-signature --binary target/release/mysync --version 0.3.0 --target linux-x86_64 --output-dir /chemin/vers/releases
```

La version indiquée doit correspondre à `mysync --version` et être supérieure à la version déjà publiée. Les forks doivent générer leur propre clé avec `mysync-release keygen --secret-key /chemin/prive/cle-signature`, remplacer la clé publique intégrée, puis reconstruire leurs clients. Le changement de clé publique n'est pas encore automatisé : les clients existants doivent être réinstallés de façon fiable pour accepter une nouvelle clé.

Pour une première installation sans compilation, obtenir le binaire versionné et son empreinte depuis une source fiable, puis vérifier cette empreinte avant de l'exécuter. La signature intégrée protège les mises à jour suivantes, pas le tout premier binaire. Si le client a été téléchargé, utiliser son chemin à la place de `./target/release/mysync` dans les commandes de configuration, puis le passer en argument à `./deploy/install-client.sh`.

L'auto-mise à jour ne modifie que `~/.local/bin/mysync`; elle ne remplace pas un exécutable installé par le gestionnaire de paquets dans `/usr/bin`. La synchronisation des fichiers continue même si la vérification d'une mise à jour échoue.

La publication locale est protégée par un verrou interprocessus et revérifie la version du binaire effectivement installé après le téléchargement. Un ancien téléchargement signé ne peut donc pas remplacer une version plus récente installée entre-temps. Si une autre installation tient le verrou, la commande échoue sans remplacer le client et peut être relancée. Ne pas supprimer `.mysync-update.lock` pendant une mise à jour.

Le client 0.3.0 teste également `--version` sur le candidat vérifié avant de remplacer le binaire installé. Attention : les anciens clients n'ont pas cette protection. Installer les bibliothèques TPM/OpenSSL sur tous les clients avant de publier une version liée à ces bibliothèques; la publication de `latest.json` déclenche les mises à jour automatiques, mais n'installe aucun paquet système et n'approuve aucun appareil.

## Limites et sécurité

Les fichiers ordinaires et leurs sous-dossiers sont synchronisés. Les dossiers vides, liens symboliques, noms non UTF-8, permissions et attributs étendus ne le sont pas. Un renommage apparaît comme une suppression puis un ajout. `.mysync-conflicts/` et `.mysync-staging/` restent locaux.

Chaque composant d'un chemin est limité à 255 octets UTF-8. Le serveur refuse les collisions entre fichiers et répertoires (par exemple `a` et `a/b` simultanément actifs), y compris lors d'une restauration. L'API et le téléchargement des mises à jour ne suivent aucune redirection HTTP ; configurer directement l'URL HTTPS finale du serveur.

Les chemins relatifs jusqu'à 4 096 octets sont parcourus par des descripteurs, même si leur chemin absolu dépasse la limite Linux. Si la surveillance native ne peut pas être installée, le client continue par interrogation toutes les 15 secondes. Les conversions dossier/fichier appliquent les suppressions avant les créations ; un sous-arbre local déplacé est conservé dans les conflits. Seuls les répertoires de récupération directement vides sont supprimés automatiquement ; les sous-arbres contenant encore des dossiers vides peuvent rester comme copies de récupération.

Les réponses JSON sont limitées avant décodage : 32 Mio pour le manifeste et la corbeille, 64 Kio pour les autres réponses. Une liste dépassant la limite fait échouer la synchronisation explicitement, sans traiter une liste tronquée ; la pagination n'est pas encore disponible. Leur lecture dispose de 30 secondes, les requêtes API ordinaires de 60 secondes au total. Les téléchargements de fichiers ont un délai total d'une heure et une limite d'inactivité de 30 secondes. Leur taille est contrôlée **avant chaque écriture**, en plus du contrôle final SHA-256 ; cela ne constitue pas un quota global de stockage.

Le serveur vérifie les preuves TPM, leur fraîcheur, leur session et leur nonce avant de lire les corps signés. Il admet au plus huit requêtes signées simultanées, chacune avec un corps de 8 Mio maximum et un délai de lecture de 30 secondes. Une surcharge renvoie HTTP 429. Un nonce consommé n'est pas réutilisable même après échec du transfert ; le client signe une nouvelle preuve lors du prochain essai. Le répertoire public des versions est ouvert au démarrage et ses fichiers sont ouverts sans suivre les liens symboliques ; pour changer ce répertoire lui-même, redémarrer le serveur.

Le client accède aux fichiers par des descripteurs de répertoire en refusant les liens symboliques. Une modification ou une création locale pendant un téléchargement est conservée dans `.mysync-conflicts/` avant d'appliquer la version du serveur. Si un remplacement échoue après la mise à l'abri du fichier local, sa copie de récupération reste dans ce dossier ; elle n'est pas supprimée par le nettoyage des téléchargements temporaires.

Une suppression est propagée, mais le serveur conserve le contenu dans une corbeille pendant 30 jours (`mysync trash`, puis `mysync restore <id>`). Les copies de conflits restent locales. Les écrasements ordinaires n'ont pas d'historique : la corbeille ne remplace pas une sauvegarde.

Les fichiers sont stockés **en clair** sur le serveur et visibles par son opérateur ainsi que par un éventuel proxy Cloudflare. Ce projet n'offre pas de chiffrement de bout en bout. Prévoir des sauvegardes chiffrées hors site et tester leur restauration. Il manque encore notamment une limite globale de stockage et un audit indépendant avant d'utiliser ce logiciel pour des données critiques. L'appartenance au groupe `docker` donne des privilèges très élevés sur l'hôte.

Le TPM protège contre la réutilisation d'une configuration copiée sur un autre TPM. Il ne protège pas contre un processus compromis disposant des mêmes droits sur la machine appairée, ni contre root, qui peuvent demander des signatures au TPM. Il n'y a pas d'attestation du démarrage ni de contrôle PCR. Un effacement du TPM ou un remplacement de carte mère nécessite la révocation puis un nouvel appairage. Les certificats sont vérifiés à l'appairage, sans consultation automatique OCSP/CRL : voir les [limites de confiance](docs/device-auth.md#garanties-et-limites).

Le [bilan des corrections de la revue de sécurité](docs/security-review-followup.md) détaille les constats vérifiés, les tests et les risques résiduels.
