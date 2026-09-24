# Installer le serveur

Le serveur tourne dans Docker Compose derrière un proxy HTTPS. Ces commandes se lancent depuis la racine d'une copie du dépôt sur l'hôte serveur. Docker avec Compose et `make` sont nécessaires ; aucun TPM n'est requis sur cet hôte.

## Préparer le stockage

Copier l'exemple, puis adapter **les quatre valeurs** au compte et aux chemins de l'hôte :

```sh
cp deploy/.env.example deploy/.env
${EDITOR:-vi} deploy/.env
```

`MYSYNC_DATA_DIR` contient les fichiers et SQLite ; `MYSYNC_RELEASES_DIR` contient seulement les versions clientes publiques. Les deux chemins doivent être absolus et distincts. `MYSYNC_UID` et `MYSYNC_GID` désignent le propriétaire des fichiers dans le conteneur. Ne placer aucune clé privée de signature, invitation ou profil client dans les releases publiques, le dépôt ou la documentation.

Créer les dossiers avant le démarrage. Ces commandes correspondent exactement aux valeurs de `deploy/.env.example` ; adapter chemins, UID et GID si le fichier a été modifié :

```sh
sudo install -d -m 0700 -o 1000 -g 1000 /srv/mysyncfiles
sudo install -d -m 0750 -o 1000 -g 1000 /srv/mysyncfiles-releases
```

`deploy/.env` est ignoré par Git. Conserver le répertoire de données et ses sauvegardes hors du dépôt. Voir la [configuration](configuration.md) pour le rôle de chaque valeur.

## Construire et démarrer

```sh
make install
make start
curl -fsS http://127.0.0.1:8484/v1/health
```

`make install` valide la configuration Compose, l'existence des dossiers et leurs chemins absolus, puis construit l'image. `make start` refait ces vérifications et lance le serveur, qui initialise SQLite dans le dossier de données. Le point de santé est accessible uniquement sur la boucle locale de l'hôte. Pour consulter les journaux ou arrêter sans effacer les données : `make logs` et `make stop`.

Les commandes directes `docker compose -f deploy/compose.yaml ...` restent disponibles. Ne jamais lancer deux serveurs sur la même base SQLite.

## Exposer une origine HTTPS

Configurer un proxy TLS qui transmet les requêtes vers `127.0.0.1:8484`, sans redirection vers HTTP. L'exemple `deploy/nginx-sync.conf` illustre le proxy HTTP **derrière une terminaison TLS** ; il ne fournit pas lui-même HTTPS et ne doit pas être exposé seul sur Internet. Garder intacts méthode, chemin, query, corps et en-têtes `Authorization` et `x-mysync-proof`. Désactiver le cache et les transformations des routes authentifiées. Les transferts par blocs de 8 Mio restent compatibles avec un proxy Cloudflare, qui peut néanmoins lire les fichiers si TLS s'y termine.

Utiliser ensuite l'[origine publique et les racines EK vérifiées](device-auth.md#configuration-du-serveur) pour exécuter `device auth-configure`. L'origine doit être l'URL HTTPS exacte vue par les clients, sans sous-chemin. Cette configuration est indispensable avant que `/install.sh` soit disponible.

## Préparer le premier client

[Publier un binaire signé](operations.md#publier-un-client-signe) pour chaque architecture cliente utilisée. Cette publication est une opération distincte de `make install` et `make start`. Tant qu'aucune release compatible n'est publiée, le script d'installation ne peut pas installer de client.

Vérifier depuis l'extérieur que l'origine HTTPS sert `/install.sh` et que le certificat TLS est valide. Créer une [invitation par appareil](install-client.md#inviter-et-approuver-un-appareil) juste avant l'appairage, puis suivre le [guide client](install-client.md).
