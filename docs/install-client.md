# Installer un client

Le client fonctionne sur Linux x86-64 ou AArch64 avec un TPM 2.0 accessible et un certificat EK constructeur correspondant. Debian 13 et Arch Linux/dérivées sont testés. Le serveur doit déjà avoir son origine HTTPS et sa confiance EK configurées, ainsi qu'une [release signée](operations.md#publier-un-client-signe) pour l'architecture du client.

Sauvegarder les fichiers importants avant la première synchronisation. Choisir un dossier miroir local distinct de la configuration privée du client.

## Installer le binaire signé

Remplacer le domaine d'exemple par l'origine HTTPS du serveur. Examiner le script avant sa première exécution :

```sh
curl -fsS https://sync.example.org/install.sh -o install.sh
cat install.sh
sh install.sh
```

Le script propose les paquets manquants sur Debian/Arch avant tout `sudo`, vérifie la signature de la release et le hash du binaire, puis contrôle l'accès au TPM. Il n'installe ni ne démarre le service si le contrôle TPM échoue ; une installation existante n'est pas remplacée. L'examen du script et la confiance dans l'origine HTTPS restent importants : la signature du binaire ne protège pas un script distant compromis.

Si le certificat EK constructeur manque dans les index NV du TPM, fournir son fichier DER obtenu auprès du fabricant :

```sh
MYSYNC_EK_CERT=/chemin/prive/ek.der sh install.sh
```

Le même certificat devra être passé à `mysync enroll --ek-cert`. Voir la [procédure et ses limites](device-auth.md#certificat-ek-absent-du-tpm). Ne pas remplacer le certificat constructeur par un certificat auto-signé.

## Inviter et approuver un appareil

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

## Activer la synchronisation

Après approbation, sur le client :

```sh
~/.local/bin/mysync enroll-activate
systemctl --user enable --now mysync.service
sudo loginctl enable-linger "$(id -un)"
~/.local/bin/mysync status
```

`enroll-activate` réalise la première synchronisation ; vérifier les fichiers et les éventuels conflits avant d'activer le service. Le *linger* permet au service utilisateur de démarrer sans session ouverte. Le script d'installation ne démarre jamais ce service avant l'appairage. Pour suivre son activité : `journalctl --user -u mysync.service -f`.

Pour un client construit depuis les sources, suivre plutôt l'[installation depuis les sources](operations.md#construire-et-installer-depuis-les-sources). Pour une erreur, consulter le [dépannage](troubleshooting.md).
