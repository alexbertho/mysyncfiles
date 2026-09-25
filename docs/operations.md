# Déploiement et publication

Le [guide d'installation serveur](install-server.md) couvre la préparation de `deploy/.env`, des volumes et du proxy HTTPS. Cette page décrit les opérations qui suivent le premier démarrage. Les chemins, noms et domaines ci-dessous sont des exemples à adapter ; les secrets restent hors du dépôt et des fichiers servis publiquement.

## Construire et installer depuis les sources

La version Rust est fixée dans `rust-toolchain.toml`. Installer Rust avec [rustup](https://rustup.rs/) dans l'espace utilisateur, sans `sudo cargo`. Pour construire et tester hors Docker :

```sh
# Debian 13
sudo apt install build-essential pkg-config libssl-dev libtss2-dev tpm2-tools swtpm swtpm-tools
# Arch Linux et dérivées
sudo pacman -S --needed base-devel pkgconf openssl tpm2-tss tpm2-tools swtpm

cargo build --release --locked
cargo test --locked
```

Les binaires sont `mysync` (client), `mysync-server` et `mysync-release`. L'[environnement Docker TPM de développement](device-auth.md#tests-et-validation) permet aussi de compiler et tester sans installer cette chaîne sur l'hôte.

Pour installer un client construit depuis les sources, exécuter `./deploy/install-tpm-deps.sh` et `./target/release/mysync doctor`, puis `./target/release/mysync setup --server URL_HTTPS --dir "$HOME/Sync"` et [appairer l'appareil](install-client.md#appairer-et-approuver-un-appareil) avec `make pair` sur le serveur. Après une première synchronisation sans conflit, lancer `./deploy/install-client.sh`. Ce script copie le binaire dans `~/.local/bin`, installe l'unité utilisateur, active le *linger* et démarre le service. Il accepte un chemin de binaire de confiance en argument. Pour un premier binaire téléchargé autrement que par `/install.sh`, vérifier sa provenance et son empreinte : une mise à jour signée ne protège pas rétroactivement ce premier téléchargement.

## Publier un client signé

Le serveur distribue `/install.sh` et les routes publiques `/v1/updates/<cible>/latest.json`, `latest.sig` et `mysync-<version>-<cible>`. Le script est intégré à l'image serveur avec sa clé publique de release ; il vérifie la signature et le SHA-256 du binaire avant de l'exécuter. Il n'écrase pas une installation existante, qui utilise `mysync update`.

La publication est une opération administrateur distincte du build serveur, de la CI et du démarrage. Elle doit être effectuée avec la clé privée correspondant à la clé publique intégrée au client **et** au serveur :

```sh
mysync-release publish --secret-key /chemin/prive/cle-signature \
  --binary target/release/mysync --version 0.3.2 \
  --target linux-x86_64 --output-dir /srv/mysyncfiles-releases
```

Publier séparément `linux-x86_64` et `linux-aarch64` avec des binaires construits et testés sur l'architecture correspondante. La version annoncée doit correspondre à `mysync --version` et dépasser celle déjà publiée. `--output-dir` désigne la racine montée dans `/releases` ; l'outil crée le sous-dossier de la cible. Le dépôt source ne garantit pas qu'un artefact signé soit disponible sur un serveur donné. Publier `latest.json` peut déclencher les mises à jour automatiques : vérifier au préalable les bibliothèques natives et le TPM des clients concernés.

Garder la clé privée hors du conteneur et du répertoire public de releases, idéalement hors ligne sur un poste de publication distinct. Un fork génère sa propre clé avec `mysync-release keygen --secret-key /chemin/prive/cle-signature`, remplace `src/update_public_key.hex`, puis reconstruit client et serveur avant publication. La rotation de la clé publique n'est pas automatisée : les anciens clients doivent être réinstallés par un canal fiable. Voir les [garanties de distribution](security.md#distribution-et-exploitation).

## Administrer les appareils

Le parcours recommandé est `make pair` : l'administrateur saisit le code affiché sur le client, attend la preuve TPM et confirme l'empreinte complète. La [procédure client](install-client.md#appairer-et-approuver-un-appareil) donne les commandes. Les sous-commandes `device` sont locales au serveur, jamais des routes HTTP d'administration. Le code enregistré expire après 15 minutes s'il n'est pas utilisé ; l'appairage en attente peut être annulé avec `device cancel --id ID --data-dir /data`. Le parcours manuel par invitation reste disponible.

Pour un appareil perdu ou compromis, exécuter `device revoke --name NOM --data-dir /data` dans le conteneur. Les nouvelles requêtes sont refusées ; une requête déjà autorisée peut terminer son traitement. Voir la [révocation et récupération](device-auth.md#revocation-et-recuperation) avant d'appairer un remplacement.

## Sauvegardes et maintenance

La base privée contient aussi la clé Ed25519 d'authenticité des réponses. `mysync-server server-key --data-dir DOSSIER` affiche sa partie publique, à transmettre aux clients par un canal fiable. Conserver cette clé avec les sauvegardes SQLite ; sa perte ou sa rotation impose de mettre à jour explicitement la clé épinglée de chaque client. La [migration des profils existants](device-auth.md#authenticite-des-reponses-et-migration) ne réinitialise ni les appareils TPM ni les fichiers.

L'état client est publié atomiquement une fois par passe modifiée, avec sérialisation tamponnée et synchronisation du fichier et du dossier parent. Un petit journal privé `config.state.journal` conserve durablement les mutations terminées entre deux publications. Il est rejoué au redémarrage ; ne pas le supprimer lors d'une récupération ou le séparer de `config.state.json` dans une sauvegarde. Une passe sans changement ne réécrit pas l'état.

Sauvegarder de façon cohérente le répertoire de données privé, qui contient la base SQLite et les blobs, ainsi que les éléments de configuration nécessaires à la restauration. Éviter une copie brute de SQLite pendant les écritures : arrêter le serveur le temps d'une copie des fichiers, ou utiliser une méthode de sauvegarde SQLite cohérente. Tester régulièrement la restauration sur un hôte isolé. Conserver les sauvegardes et la clé privée hors du dépôt et du répertoire de releases. MySyncFiles ne remplace pas ces sauvegardes : les écrasements ordinaires n'ont pas d'historique restaurable.

`make logs`, `make stop` et `make start` pilotent le serveur sans supprimer les volumes. Les commandes directes `docker compose -f deploy/compose.yaml ...` restent utilisables. Ne pas démarrer deux serveurs sur la même base.

L'appartenance au groupe `docker` accorde des privilèges élevés sur l'hôte. Réserver les commandes Compose aux administrateurs autorisés.

La documentation se prévisualise indépendamment avec `make docs` sur `http://127.0.0.1:8000`, s'arrête avec `make docs-stop` et se valide avec `make docs-check`. Ce service local n'expose ni les données du serveur ni `deploy/.env`.

## Publier la documentation

La prévisualisation MkDocs est réservée au poste local. Pour servir la documentation sur l'origine HTTPS du serveur à `/docs/`, construire des fichiers statiques, puis les faire servir par le proxy existant. Cette opération ne change ni l'API, ni l'origine configurée pour les clients TPM.

Depuis la racine du dépôt, fournir l'URL publique **avec le slash final** au build. La valeur est utilisée pour les liens canoniques et le sitemap ; elle n'est pas enregistrée dans le dépôt public :

```sh
MYSYNC_DOCS_SITE_URL=https://sync.example.org/docs/ make docs-build
```

`site/` est généré localement et ignoré par Git. Sur l'hôte du proxy, installer les fichiers dans le répertoire réservé à la documentation :

```sh
sudo install -d -m 0755 /var/www/mysyncfiles/docs
sudo rsync -a --delete site/ /var/www/mysyncfiles/docs/
```

Dans le **bloc HTTPS** Nginx de l'origine publique, placer les deux locations `/docs` et `/docs/` du modèle `deploy/nginx-sync.conf` avant la location générale `/`. Le répertoire `/var/www/mysyncfiles/docs/` doit rester distinct du stockage serveur et des releases. Vérifier puis recharger Nginx :

```sh
sudo nginx -t
sudo systemctl reload nginx
curl -fsSI https://sync.example.org/docs/
```

`/docs` redirige vers `/docs/` pour que les liens relatifs fonctionnent. Les autres chemins continuent vers le serveur MySyncFiles, avec leurs règles de cache et d'authentification actuelles. Pour mettre les pages à jour, reconstruire avec la même URL puis recopier `site/` ; il n'est pas nécessaire de redémarrer le serveur ou le service de prévisualisation. Ne pas exposer `site/` depuis le répertoire de données privé du serveur.
