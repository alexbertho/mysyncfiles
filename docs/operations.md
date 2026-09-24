# Exploitation et publication

Ce guide complète le [démarrage rapide](../README.md). Les chemins et le domaine sont des exemples à adapter. Ne placez jamais une clé privée, une invitation ou une base de données dans le dépôt public.

## Construire et tester

La version de Rust est fixée dans `rust-toolchain.toml`. Installer la chaîne via [rustup](https://rustup.rs/) dans l'espace utilisateur, sans `sudo cargo`. Les dépendances de compilation et de test sont :

```sh
# Debian 13
sudo apt install build-essential pkg-config libssl-dev libtss2-dev tpm2-tools swtpm swtpm-tools
# Arch Linux et dérivées
sudo pacman -S --needed base-devel pkgconf openssl tpm2-tss tpm2-tools swtpm

cargo build --release --locked
cargo test --locked
```

Les binaires sont `mysync` (client), `mysync-server` et `mysync-release`. L'[environnement Docker de développement](device-auth.md#tests-et-validation) permet de compiler et tester sans installer la chaîne Rust sur l'hôte ; ses TPM sont simulés et isolés.

## Déployer le serveur

Le serveur est fourni avec [Docker Compose](../deploy/compose.yaml). Le conteneur est non privilégié, en lecture seule, sans capacités Linux, et n'écoute sur l'hôte qu'en `127.0.0.1:8484`. Un proxy HTTPS, par exemple [Nginx](../deploy/nginx-sync.conf), doit exposer l'origine publique. Cloudflare peut rester en mode proxy : les envois de fichiers sont divisés en blocs de 8 Mio. Ne mettez pas en cache les routes authentifiées et ne transformez pas leurs méthodes, chemins, corps ou en-têtes.

Créer séparément un dossier privé pour les fichiers et SQLite (mode `0700`) et un dossier en lecture pour les versions du client. Copier `deploy/.env.example` vers `deploy/.env`, puis y définir les chemins absolus et l'UID/GID propriétaires. `deploy/.env` est ignoré par Git.

```sh
docker compose -f deploy/compose.yaml build
docker compose -f deploy/compose.yaml up -d
curl -fsS http://127.0.0.1:8484/v1/health
```

Ne lancez pas deux serveurs sur la même base SQLite. Le volume des versions ne doit contenir **aucune clé privée**. Le serveur n'a pas besoin de TPM : son image contient les outils nécessaires à l'attestation. La configuration de l'origine HTTPS, des autorités EK constructeur et de l'approbation des appareils est décrite dans le [guide d'identité TPM](device-auth.md#configuration-du-serveur). L'URL `/install.sh` répond seulement après configuration de l'origine publique.

Pour chaque appareil, créer une invitation distincte, valide 15 minutes. `--output` l'enregistre en mode `0600` sans l'afficher :

```sh
install -d -m 700 "$HOME/.local/share/mysync-keys"
docker compose -f deploy/compose.yaml run --rm -v "$HOME/.local/share/mysync-keys:/keys" server device invite --data-dir /data --name nouvel-appareil --output /keys/nouvel-appareil.key
docker compose -f deploy/compose.yaml run --rm server device pending --data-dir /data
```

Après comparaison de l'empreinte reçue directement du client, approuver avec `device approve --data-dir /data --id ID_APPARIAGE --fingerprint EMPREINTE_CLIENT`. Une invitation ou une empreinte provenant seulement du serveur ne suffit pas à vérifier l'appareil. Un appareil compromis ou perdu se révoque avec `device revoke --data-dir /data --name NOM` ; ses nouvelles requêtes sont refusées, mais une requête déjà autorisée peut terminer son traitement.

## Distribuer le client

Les routes publiques `/v1/updates/<cible>/latest.json`, `latest.sig` et `mysync-<version>-<cible>` distribuent un manifeste Ed25519 signé et son binaire. `/install.sh` est compilé dans l'image serveur, avec la même clé publique que le client et l'origine HTTPS configurée. Le script vérifie la signature et le SHA-256 **avant** d'exécuter le candidat, puis vérifie le TPM sans créer d'identité. Il ne remplace jamais une installation existante : les clients déjà installés utilisent `mysync update`.

La publication est une opération administrateur séparée, pas une étape de CI :

```sh
mysync-release publish --secret-key /chemin/prive/cle-signature --binary target/release/mysync --version 0.3.2 --target linux-x86_64 --output-dir /chemin/vers/releases
```

Publier séparément un artefact pour `linux-x86_64` et `linux-aarch64`, compilé et testé pour l'architecture correspondante. La version indiquée doit correspondre à `mysync --version` et dépasser la version déjà publiée. Le dépôt source ne garantit pas qu'un artefact signé soit déjà disponible sur un serveur donné. Une publication de `latest.json` déclenche les mises à jour automatiques : vérifier au préalable les bibliothèques natives et le TPM sur les machines cibles. La clé privée doit idéalement être gardée hors ligne, jamais montée dans le conteneur.

Les forks génèrent leur propre clé avec `mysync-release keygen --secret-key /chemin/prive/cle-signature`, remplacent [`src/update_public_key.hex`](../src/update_public_key.hex), puis reconstruisent **client et serveur**. Une rotation de la clé publique n'est pas automatisée : les anciens clients doivent être réinstallés par un canal fiable.

Le client vérifie les nouvelles versions au démarrage puis toutes les six heures. La version signée, l'architecture, la taille et le SHA-256 sont contrôlés avant remplacement atomique de `~/.local/bin/mysync`. Le téléchargement et la publication locale sont verrouillés pour éviter qu'un téléchargement ancien ne rétrograde un client plus récent. Une erreur de mise à jour ne bloque pas la synchronisation. Ne supprimez pas `.mysync-update.lock` pendant une mise à jour. Une installation sous `/usr/bin` n'est pas remplacée automatiquement. Le démon garde sa clé chargée dans le TPM et sa session API en mémoire entre les passages ; chaque requête conserve néanmoins sa propre preuve TPM fraîche. Une commande CLI indépendante doit charger la clé une fois au démarrage.

## Installer un client depuis les sources

Après construction, exécuter `./deploy/install-tpm-deps.sh`, puis `./target/release/mysync doctor`. Une fois l'appairage TPM et l'activation terminés, `./deploy/install-client.sh` copie le binaire vers `~/.local/bin`, installe l'unité utilisateur et active le *linger* systemd. Le script accepte aussi le chemin d'un binaire de confiance en argument. Pour une première installation téléchargée hors de `/install.sh`, vérifier son origine et son empreinte avant de l'exécuter ; la mise à jour signée ne protège pas rétroactivement le premier téléchargement.

## Limites et sécurité

Les fichiers ordinaires et leurs sous-dossiers sont synchronisés. Les dossiers vides, liens symboliques, noms non UTF-8, permissions et attributs étendus ne le sont pas. Un renommage apparaît comme une suppression puis un ajout. `.mysync-conflicts/` et `.mysync-staging/` restent locaux. Le client refuse les liens symboliques pendant les opérations sur le miroir et préserve dans `.mysync-conflicts/` une modification locale survenue pendant un téléchargement.

Une suppression est propagée mais le serveur garde le contenu en corbeille pendant 30 jours (`mysync trash`, puis `mysync restore <id>`). Les écrasements ordinaires n'ont **pas** d'historique restaurable : prévoir des sauvegardes chiffrées hors site et tester leur restauration. Les fichiers et la base sont en clair sur le serveur ; l'opérateur et un proxy Cloudflare peuvent les lire. Il n'y a pas de chiffrement de bout en bout, pas de quota global et pas encore d'audit indépendant. L'appartenance au groupe `docker` donne des privilèges élevés sur l'hôte.

Chaque composant de chemin est limité à 255 octets UTF-8. Le serveur refuse les collisions entre fichier et répertoire. Les chemins relatifs jusqu'à 4 096 octets sont traités par descripteurs ; si la surveillance native échoue, le client continue par interrogation toutes les 15 secondes. Les listes JSON sont bornées (32 Mio pour manifeste/corbeille, 64 Kio pour les autres réponses) ; elles ne sont pas paginées, donc une liste trop grande fait échouer la synchronisation sans être tronquée. Les transferts ont aussi des délais, des limites de taille et des contrôles de hash.

L'API et les téléchargements de versions ne suivent aucune redirection. Les requêtes authentifiées portent une preuve TPM fraîche, liée au corps et à l'URL ; le serveur limite les requêtes simultanées et les corps signés à 8 Mio par requête. Le TPM empêche de réutiliser une configuration copiée sur un autre TPM, mais ne protège pas contre un processus compromis disposant de l'accès local au TPM, ni contre root. Aucun contrôle PCR/Secure Boot ou OCSP/CRL automatique n'est effectué. Après effacement du TPM ou changement de carte mère, il faut révoquer puis appairer un nouvel appareil. Voir les [garanties de l'identité TPM](device-auth.md#garanties-et-limites) et le [suivi de la revue de sécurité](security-review-followup.md).
