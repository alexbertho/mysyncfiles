# Installer un client

Le client fonctionne sur Linux x86-64 ou AArch64 avec un TPM 2.0 accessible et un certificat EK constructeur correspondant. Debian 13 et Arch Linux/dérivées sont testés. Le serveur doit déjà avoir son origine HTTPS et sa confiance EK configurées, ainsi qu'une [release signée](operations.md#publier-un-client-signe) pour l'architecture du client.

Sauvegarder les fichiers importants avant la première synchronisation. Choisir un dossier miroir local distinct de la configuration privée du client.

## Installer le binaire signé

Remplacer le domaine d'exemple par l'origine HTTPS du serveur. Dans un terminal :

```sh
curl -fsS --proto '=https' --max-redirs 0 https://sync.example.org/install.sh | sh
```

Pour examiner le script avant sa première exécution, le télécharger dans un fichier, le lire, puis lancer `sh install.sh`. Le script utilise `/dev/tty` pour les questions interactives : l'appairage fonctionne aussi lorsque le script est transmis à `sh` par un pipe.

Le script propose les paquets manquants sur Debian/Arch avant tout `sudo`, vérifie la signature de la release et le hash du binaire, puis contrôle l'accès au TPM. Dans un terminal, il demande le dossier miroir, affiche un code temporaire et attend l'administrateur. Il lance la première synchronisation puis le service utilisateur seulement si l'appairage réussit et qu'aucun conflit ne reste dans `.mysync-conflicts/`. Une unité systemd existante différente est laissée intacte et n'est pas démarrée automatiquement. Sans terminal, il installe le binaire et l'unité sans appairer ni démarrer le service. Une installation existante n'est pas remplacée. L'examen du script et la confiance dans l'origine HTTPS restent importants : la signature du binaire ne protège pas un script distant compromis.

Si le certificat EK constructeur manque dans les index NV du TPM, fournir son fichier DER obtenu auprès du fabricant :

```sh
curl -fsS --proto '=https' --max-redirs 0 https://sync.example.org/install.sh | MYSYNC_EK_CERT=/chemin/prive/ek.der sh
```

L'installateur transmet le même certificat à `mysync setup`. Pour des intermédiaires EK constructeur, définir `MYSYNC_EK_CHAIN=/chemin/intermediaires.pem` lors de l'installation. Voir la [procédure et ses limites](device-auth.md#certificat-ek-absent-du-tpm). Ne pas remplacer le certificat constructeur par un certificat auto-signé.

## Appairer et approuver un appareil

Le client affiche un code à usage unique, puis attend. Sur l'hôte serveur, depuis le dépôt et avec `deploy/.env` configuré :

```sh
make pair
```

Saisir le nom de l'appareil et le code affiché sur le client. Après vérification du certificat EK et de la preuve TPM, comparer **l'empreinte complète** affichée par les deux commandes, par un canal fiable, puis confirmer sur le serveur. Le code seul ne donne pas accès aux fichiers. Il est enregistré sous forme de hash et expire au bout de 15 minutes s'il n'a pas été utilisé. La commande serveur et le client peuvent être relancés pour reprendre une demande en cours ; une demande expirée ou annulée nécessite un nouveau code. Le client attend au plus 30 minutes par exécution.

Si l'installateur a été lancé sans terminal, démarrer l'appairage sur le client avec :

```sh
~/.local/bin/mysync setup --server https://sync.example.org --dir "$HOME/Sync"
```

Ajouter `--ek-cert /chemin/ek.der` et `--ek-chain /chemin/intermediaires.pem` si nécessaire. Après la première synchronisation, examiner les éventuels fichiers dans `.mysync-conflicts/` avant d'activer le service. Si `mysync setup` a réussi sans conflit hors de l'installateur, démarrer le service avec `systemctl --user enable --now mysync.service`. Pour un démarrage sans session ouverte : `sudo loginctl enable-linger "$(id -un)"`.

## Parcours manuel avec invitation

Sur le serveur, l'administrateur crée une invitation distincte et la transmet par un canal confidentiel. Le chemin privé ci-dessous est un exemple ; il doit être accessible en écriture à l'UID/GID du conteneur :

```sh
install -d -m 0700 "$HOME/.local/share/mysync-keys"
docker compose -f deploy/compose.yaml run --rm \
  -v "$HOME/.local/share/mysync-keys:/keys" \
  server device invite --data-dir /data --name nouvel-appareil \
  --output /keys/nouvel-appareil.key
```

Sur le client, après réception du fichier d'invitation :

```sh
~/.local/bin/mysync enroll --server https://sync.example.org \
  --dir "$HOME/Sync" --invitation-stdin < /chemin/prive/invitation
```

Ajouter `--ek-cert /chemin/prive/ek.der` si le certificat n'est pas stocké dans le TPM, et `--ek-chain` si des intermédiaires constructeur vérifiés sont nécessaires. Le client affiche un identifiant et une empreinte. L'administrateur compare l'empreinte reçue **directement du client** à celle affichée par le serveur, par un canal fiable :

```sh
docker compose -f deploy/compose.yaml run --rm \
  server device pending --data-dir /data
docker compose -f deploy/compose.yaml run --rm \
  server device approve --data-dir /data \
  --id ID_APPARIAGE --fingerprint EMPREINTE_CLIENT
```

L'invitation seule ne donne pas accès aux fichiers. Les détails et la [révocation](device-auth.md#revocation-et-recuperation) sont dans le guide TPM.

## Activer la synchronisation manuelle

Après approbation, sur le client :

```sh
~/.local/bin/mysync enroll-activate
systemctl --user enable --now mysync.service
sudo loginctl enable-linger "$(id -un)"
~/.local/bin/mysync status
```

`enroll-activate` réalise la première synchronisation ; vérifier les fichiers et les éventuels conflits avant d'activer le service. Le *linger* permet au service utilisateur de démarrer sans session ouverte. Le script d'installation ne démarre jamais ce service avant l'appairage. Pour suivre son activité : `journalctl --user -u mysync.service -f`.

Pour un client construit depuis les sources, suivre plutôt l'[installation depuis les sources](operations.md#construire-et-installer-depuis-les-sources). Pour une erreur, consulter le [dépannage](troubleshooting.md).
