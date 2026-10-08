# Déploiement et publication

Le [guide d'installation serveur](install-server.md) couvre la préparation de `deploy/.env`, des volumes et du proxy HTTPS. Cette page décrit les opérations qui suivent le premier démarrage. Les chemins et noms ci-dessous sont des exemples à adapter. Dans le dépôt source, le domaine est aussi un exemple ; le site publié utilise l'origine configurée par l'administrateur. Les secrets restent hors du dépôt et des fichiers servis publiquement.

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

Pour préparer seulement le client et l'outil de publication, lancer `make build-client`. Cette cible construit `target/release/mysync` et `target/release/mysync-release`, avec une tâche Cargo par défaut et le conteneur TPM si nécessaire. Elle ne remplace aucun client installé et ne publie aucune release.

Pour installer un client construit depuis les sources, exécuter `./deploy/install-tpm-deps.sh` et `./target/release/mysync doctor`, puis `./target/release/mysync setup --server URL_HTTPS --dir "$HOME/Sync"` et [appairer l'appareil](install-client.md#appairer-et-approuver-un-appareil) avec `make pair` sur le serveur. Après une première synchronisation sans conflit, lancer `./deploy/install-client.sh`. Ce script copie le binaire dans `~/.local/bin`, installe l'unité utilisateur, active le *linger* et démarre le service. Il accepte un chemin de binaire de confiance en argument. Pour un premier binaire téléchargé autrement que par `/install.sh`, vérifier sa provenance et son empreinte : une mise à jour signée ne protège pas rétroactivement ce premier téléchargement.

## Publier un client signé

Le serveur distribue `/install.sh` et les routes publiques `/v1/updates/<cible>/latest.signed.json`, `latest.json`, `latest.sig` et `mysync-<version>-<cible>`. L'enveloppe `latest.signed.json` associe atomiquement le manifeste signé ; les deux anciens fichiers restent publiés pour les clients déjà installés. Les clients récents ne retombent sur le format précédent que si l'enveloppe répond `404`, jamais si sa signature est invalide. Le script est intégré à l'image serveur avec sa clé publique de release ; il vérifie la signature et le SHA-256 du binaire et la présence de `mysync setup` avant de l'exécuter. L'outil de publication vérifie aussi que le binaire annonce la bonne version et accepte `setup --help` avant de le signer. Si un binaire déjà installé diffère de la release signée, l'installateur demande confirmation avant de conserver une copie et de le remplacer ; il refuse une version installée plus récente. `mysync update` reste disponible pour les profils clients déjà configurés.

La publication est une opération administrateur distincte du build serveur, de la CI et du démarrage. Elle doit être effectuée avec la clé privée correspondant à la clé publique intégrée au client **et** au serveur :

Avant la compilation, augmenter la version du paquet dans `Cargo.toml` et son entrée `mysyncfiles` dans `Cargo.lock`, puis lancer `make test` et `make build-client`. Une modification du client conservant le numéro déjà publié ne sera pas installée par `mysync update`. Vérifier le binaire construit sur les distributions ciblées avant publication. La fonctionnalité de présence locale apparaît dans la version **0.3.7**.

La version **0.3.8** active cette présence par défaut et ajoute `mysync web-status` et `setup --web-status true|false`. La question de l’installateur HTTPS nécessite aussi le déploiement du serveur qui embarque `deploy/install.sh` ; publier uniquement le client ne remplace pas ce script. L’installateur depuis les sources propose également le réglage et accepte `MYSYNC_WEB_STATUS=true|false`.

La version **0.3.9** améliore les scans SHA-256, les transferts et la préparation
de `status` et `sync`, et corrige la pagination des grands manifestes. Le nouveau
client fonctionne avec les serveurs précédents ; le résumé signé utilisé par
`status` nécessite le nouveau serveur pour réduire le nombre de requêtes. Les
profils, signatures, contrôles de révision et copies de conflits restent compatibles.

La version **0.3.10** ajoute l’autorisation de lecture web `mysync web-files` pour l’explorateur Atlas. Le client 0.3.9 publié ne peut vérifier que la présence `/status` ; publier cette nouvelle version cliente signée est nécessaire pour utiliser `/files`. Après `mysync update`, arrêter le daemon avant `mysync web-files enable`, puis relancer le service déjà installé. Ce consentement reste désactivé par défaut. Le serveur doit également inclure Atlas ; son interface HTML/CSS/JavaScript native se modifie ensuite à chaud dans `web/`. Voir le [guide d’activation](web-files.md).

La version **0.3.11** ajoute des routes d’envoi au serveur et le consentement client distinct `mysync web-files enable-upload` pour le glisser-déposer. Elle nécessite une reconstruction du serveur et la publication de cette release cliente signée ; remplacer seulement les fichiers `web/` ne suffit pas. Un client 0.3.10 ne connaît pas `enable-upload`. La reconstruction, le déploiement, la publication signée et l’activation du consentement sont des opérations distinctes. Voir [ajouter des fichiers](web-files.md#ajouter-des-fichiers).

La version **0.3.12** ajoute la gestion des dossiers Atlas et le consentement client distinct `mysync web-files enable-manage`. Elle exige une mise à jour du serveur et une release cliente signée publiée séparément. Les consentements de lecture et d’envoi n’accordent pas la gestion des dossiers. Voir [gérer les dossiers](web-files.md#gerer-les-dossiers).

La version **0.3.13** ajoute l’éditeur Python/C, la sauvegarde web d’un fichier existant et l’exécution isolée sur le PC du navigateur. Elle nécessite une reconstruction du serveur et la publication du client signé. Après mise à jour du client, les commandes `mysync web-files enable-edit` et `mysync web-files enable-run` accordent séparément ces consentements, désactivés par défaut. Voir les [autorisations et prérequis de l’éditeur](web-code-editor.md).

```sh
mysync-release publish --secret-key /chemin/prive/cle-signature \
  --binary target/release/mysync --version VERSION \
  --target linux-x86_64 --output-dir /srv/mysyncfiles-releases
```

Publier séparément `linux-x86_64` et `linux-aarch64` avec des binaires construits et testés sur l'architecture correspondante. La version annoncée doit correspondre à `mysync --version` et dépasser celle déjà publiée. `--output-dir` désigne la racine montée dans `/releases` ; l'outil crée le sous-dossier de la cible. Le dépôt source ne garantit pas qu'un artefact signé soit disponible sur un serveur donné. La publication de `latest.signed.json` peut déclencher les mises à jour automatiques : vérifier au préalable les bibliothèques natives et le TPM des clients concernés.

Après publication, exécuter `mysync update` puis `mysync --version` sur un client. Si aucune mise à jour n'est installée, la commande indique la version du client et celle de la dernière release signée proposée par ce serveur. Relancer le daemon après une installation manuelle pour qu'il utilise le nouveau binaire. `make deploy` met à jour le serveur et la documentation ; les clients continuent à recevoir la release précédemment publiée tant que cette étape de publication n'a pas eu lieu.

Garder la clé privée hors du conteneur et du répertoire public de releases, idéalement hors ligne sur un poste de publication distinct. Un fork génère sa propre clé avec `mysync-release keygen --secret-key /chemin/prive/cle-signature`, remplace `src/update_public_key.hex`, puis reconstruit client et serveur avant publication. La rotation de la clé publique n'est pas automatisée : les anciens clients doivent être réinstallés par un canal fiable. Voir les [garanties de distribution](security.md#distribution-et-exploitation).

## Administrer les appareils

Le parcours recommandé est `make pair` : l'administrateur saisit le code affiché sur le client, attend la preuve TPM et confirme l'empreinte complète. La [procédure client](install-client.md#appairer-et-approuver-un-appareil) donne les commandes. Les sous-commandes `device` sont locales au serveur, jamais des routes HTTP d'administration. Le code enregistré expire après 15 minutes s'il n'est pas utilisé ; l'appairage en attente peut être annulé avec `device cancel --id ID --data-dir /data`. Le parcours manuel par invitation reste disponible.

Pour un appareil perdu ou compromis, exécuter `device revoke --name NOM --data-dir /data` dans le conteneur. Les nouvelles requêtes sont refusées ; une requête déjà autorisée peut terminer son traitement. Voir la [révocation et récupération](device-auth.md#revocation-et-recuperation) avant d'appairer un remplacement.

## Sauvegardes et maintenance

La base privée contient aussi la clé Ed25519 d'authenticité des réponses. `mysync-server server-key --data-dir DOSSIER` affiche sa partie publique, à transmettre aux clients par un canal fiable. Conserver cette clé avec les sauvegardes SQLite ; sa perte ou sa rotation impose de mettre à jour explicitement la clé épinglée de chaque client. La [migration des profils existants](device-auth.md#authenticite-des-reponses-et-migration) ne réinitialise ni les appareils TPM ni les fichiers.

L'état client est publié atomiquement une fois par passe modifiée, avec sérialisation tamponnée et synchronisation du fichier et du dossier parent. Un petit journal privé `config.state.journal` conserve durablement les mutations terminées entre deux publications. Il est rejoué au redémarrage ; ne pas le supprimer lors d'une récupération ou le séparer de `config.state.json` dans une sauvegarde. Une passe sans changement ne réécrit pas l'état.

Sauvegarder de façon cohérente le répertoire de données privé, qui contient la base SQLite et les blobs, ainsi que les éléments de configuration nécessaires à la restauration. Éviter une copie brute de SQLite pendant les écritures : arrêter le serveur le temps d'une copie des fichiers, ou utiliser une méthode de sauvegarde SQLite cohérente. Tester régulièrement la restauration sur un hôte isolé. Conserver les sauvegardes et la clé privée hors du dépôt et du répertoire de releases. MySyncFiles ne remplace pas ces sauvegardes : les écrasements ordinaires n'ont pas d'historique restaurable.

`make test` vérifie l'installateur, le formatage Rust, les tests Rust, le rendu des URL de documentation et le build MkDocs. Si les bibliothèques TPM manquent sur l'hôte, les tests Rust passent dans `deploy/Dockerfile.tpm-dev`. Les compilations Cargo utilisent une tâche par défaut. Les conteneurs de développement et les étapes de construction Rust via Buildx sont limités à 3 Gio de mémoire ; les conteneurs de test et de compilation cliente disposent de deux processeurs. `MYSYNC_BUILD_MEMORY` ajuste la limite mémoire, `MYSYNC_TEST_CPUS` les processeurs de ces conteneurs et `MYSYNC_CARGO_JOBS` les tâches Cargo des tests et du client ; l'image serveur reste compilée avec une tâche. `make test`, `make install` et `make build-client` prennent un verrou sur le répertoire du projet et refusent de lancer deux compilations en parallèle. Une limite mémoire atteinte fait échouer le build ou le test ; elle évite qu'il épuise la mémoire de l'hôte.

`make deploy` lance les contrôles, valide `deploy/.env`, reconstruit l'image, génère la documentation avec l'origine configurée, recrée le service serveur et copie `site/` vers `/var/www/mysyncfiles/docs/` (ou `MYSYNC_DOCS_DIR`). Il faut Docker Compose, Docker Buildx, `flock`, Rust, Python 3, `rsync` et `sudo` sur l'hôte de déploiement. Cette commande ne publie pas de binaire client signé. `make clean` supprime seulement `target/` et `site/` ; les données privées, releases et fichiers déjà déployés restent en place.

`make logs`, `make stop` et `make start` pilotent le serveur sans supprimer les volumes. Les commandes directes `docker compose -f deploy/compose.yaml ...` restent utilisables. Ne pas démarrer deux serveurs sur la même base.

L'appartenance au groupe `docker` accorde des privilèges élevés sur l'hôte. Réserver les commandes Compose aux administrateurs autorisés.

La documentation se prévisualise indépendamment avec `make docs` sur `http://127.0.0.1:8000`, s'arrête avec `make docs-stop` et se valide avec `make docs-check`. Ce service local n'expose ni les données du serveur ni `deploy/.env`.

## Modifier l’interface web à chaud

L’interface native est dans `web/` : `index.html` pour la page, `status.css` pour les styles, `atlas.js` et `status.js` pour les interactions, avec les images et icônes à côté. Ces fichiers sont indépendants du binaire Rust et ne nécessitent ni npm ni compilation.

Docker Compose monte le dossier `web/` du dépôt dans `/web` en lecture seule. Après une modification, actualiser le navigateur : le serveur relit les fichiers à chaque requête et envoie `Cache-Control: no-store`. Une édition HTML/CSS/JavaScript ne nécessite ni `make install`, ni `make deploy`, ni redémarrage. Le montage porte sur le dossier entier, ce qui permet aussi les remplacements atomiques de fichiers par un éditeur.

Pour passer d’un ancien serveur avec interface embarquée à ce fonctionnement, une première reconstruction de l’image et une recréation du conteneur sont nécessaires, par la procédure de déploiement habituelle. Les retouches suivantes se font directement dans `web/`. Une image utilisée sans Compose contient également une copie de ces fichiers dans `/web` ; monter un dossier externe pour pouvoir les modifier à chaud.

Hors Docker, `mysync-server serve --web-dir /chemin/vers/web` indique le dossier public ; sa valeur par défaut est `web`, relative au répertoire de lancement. Conserver les autres arguments habituels, notamment `--data-dir`. Distribuer ce dossier avec le serveur lors d’une installation binaire.

Les routes `/`, `/index.html`, `/files`, `/editor` et `/status` servent le même HTML. Seuls les fichiers de l’interface explicitement exposés sont accessibles, sans parcours de répertoire. Les lectures refusent les liens symboliques et les fichiers de plus de 1 Mio. Les clés, profils et données synchronisées restent dans leurs répertoires privés. Un fichier web absent ou invalide produit une erreur `503` ; le remplacer rétablit la page sans redémarrage.

Le moteur de l’éditeur est livré dans `web/editor.js`, avec ses sources dans
`web/editor-src/` et les licences tierces dans `web/editor.LICENSE`. Après une
modification de ces sources, utiliser `make editor-build` (Node.js 20 ou plus
récent et npm). `make editor-check` vérifie que le bundle correspond aux sources
et aux dépendances verrouillées dans `web/package-lock.json`. Le serveur ne
nécessite pas Node.js et aucun script n’est téléchargé depuis un CDN. Les styles
de CodeMirror sont isolés dans un ShadowRoot ; la politique CSP conserve
`script-src 'self'` et `style-src 'self'`, sans exception pour du code inline.

## Mesurer les performances

`make benchmark` construit des binaires release et mesure de vrais processus
`mysync` face à un serveur local isolé, avec appairage et signatures via `swtpm`.
Les profils, clés et fichiers de test sont temporaires. Cette cible ne contacte
pas le serveur configuré dans `deploy/.env`. Elle utilise le même environnement
TPM que `make test` ; Python 3 et Linux sont nécessaires.

```sh
make benchmark > benchmark.jsonl
make benchmark MYSYNC_BENCH_ARGS='--suite metadata --repetitions 5 --work-dir target' > metadata.jsonl
```

Les suites disponibles sont `metadata`, `transfer`, `overwrite`, `daemon`, `concurrent` et
`all`. Elles couvrent 100 et 10 000 fichiers de 4 Kio, les transferts de 100 et
1 000 petits fichiers, trois fichiers de 64 Mio, un miroir de 512 Mio, les
conflits, les remplacements ordinaires et 35 secondes de daemon au repos. `--delay-ms 40` ajoute 40 ms à chaque
réponse HTTP pour étudier le coût des allers-retours. `--binary CHEMIN` permet
de mesurer un autre client face au même serveur de benchmark.

Chaque mesure de commande contient le temps total, le CPU utilisateur/système, le pic
RSS du client, les blocs de 512 octets lus/écrits (`getrusage`), les requêtes HTTP
et les étapes de `status`/`sync`. Les compteurs d'I/O logiques dans `/proc` sont
échantillonnés toutes les 2 ms et peuvent manquer les toutes dernières opérations.
`scan` comprend parcours, métadonnées, lectures et SHA-256 ; `apply` comprend les
transferts et le journal durable. Certaines étapes s'exécutent simultanément :
leurs durées ne doivent pas être additionnées. Les timings ne sont activés que
par `MYSYNC_BENCH_TIMINGS=1` et n'incluent ni chemins ni contenus privés.
Les compteurs `harness_io_*` incluent le serveur de test et ses processus enfants
terminés ; ils ne permettent pas d'isoler les I/O du serveur.

Le serveur traite les opérations bloquantes avec huit tâches au maximum et
conserve sa limite de huit corps de requête signés en mémoire. Une requête
authentifiée peut attendre jusqu'à 250 ms qu'une place se libère avant de recevoir
HTTP 429 ; cette attente ne lit pas son corps et ne garde pas le verrou SQLite.

Comparer les médianes de plusieurs répétitions, avec le même matériel, quota
CPU, filesystem et état de cache, sans compiler pendant les mesures. Les scans
sont normalement servis par le cache du noyau : zéro bloc physique lu ne signifie
pas zéro lecture logique. Le serveur et les TPM simulés partagent le quota CPU
du benchmark ; ce test sur loopback ne mesure pas le TLS ni un TPM matériel.
Les scénarios de concurrence indiquent aussi les latences p50/p95 et le retard
maximal d'un timer Tokio. Vérifier `returncode` et les compteurs de fichiers avant
de comparer un ancien client : les versions qui reprennent après le curseur
`next` peuvent omettre une entrée à chaque page du manifeste.

## Publier la documentation

La prévisualisation MkDocs est réservée au poste local. Pour servir la documentation sur l'origine HTTPS du serveur à `/docs/`, construire des fichiers statiques, puis les faire servir par le proxy existant. Cette opération ne change ni l'API, ni l'origine configurée pour les clients TPM.

Depuis la racine du dépôt, générer le site après `device auth-configure`. `make docs-build` lit l'origine HTTPS enregistrée par l'administrateur dans la base serveur. Elle sert aux commandes d'installation, aux liens canoniques et au sitemap ; elle n'est pas enregistrée dans le dépôt public :

```sh
make docs-build
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

`/docs` redirige vers `/docs/` pour que les liens relatifs fonctionnent. Les autres chemins continuent vers le serveur MySyncFiles, avec leurs règles de cache et d'authentification actuelles. Pour mettre les pages à jour sans redémarrer le serveur, reconstruire avec `make docs-build` puis recopier `site/`. `make deploy` effectue ces opérations après les tests et la reconstruction du serveur. Ne pas exposer `site/` depuis le répertoire de données privé du serveur.
