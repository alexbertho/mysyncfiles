# MySyncFiles

MySyncFiles garde un dossier Linux synchronisé entre plusieurs appareils. Le serveur conserve les fichiers et tranche les conflits ; une modification locale perdante reste récupérable dans `.mysync-conflicts/`. Le client peut tourner en arrière-plan et démarrer avec la machine.

> **À savoir :** les fichiers sont stockés en clair sur le serveur et peuvent être lus par son opérateur ou son proxy HTTPS. Ce logiciel ne remplace pas une sauvegarde et n'a pas encore fait l'objet d'un audit indépendant.

## Démarrage rapide

Il faut un serveur MySyncFiles accessible en HTTPS, un client Linux x86-64 ou AArch64 et un TPM 2.0 avec certificat constructeur EK. Le certificat peut être dans le TPM ou fourni en fichier DER obtenu auprès du fabricant. Debian 13 et Arch Linux/dérivées sont testées ; les autres distributions sont tentées si leurs bibliothèques natives sont compatibles. Le serveur n'a pas besoin de TPM. Voir [déploiement du serveur et publication d'une version signée](docs/operations.md) avant d'installer le premier client.

Sur chaque client, remplacer le domaine d'exemple par celui du serveur :

```sh
curl -fsS https://sync.example.org/install.sh | sh
```

Le script affiche les étapes, propose les paquets manquants sur Debian/Arch **avant** tout `sudo`, vérifie la signature du client et diagnostique le TPM. Sans TPM utilisable, il s'arrête sans installer ni démarrer le service. Il n'écrase pas un client déjà installé. Pour examiner le script avant de l'exécuter :

```sh
curl -fsS https://sync.example.org/install.sh -o install.sh
less install.sh
sh install.sh
```

Une première exécution de `curl | sh` suppose que l'URL HTTPS et son proxy servent le bon script. La signature protège le binaire téléchargé, pas un script distant compromis.

Si le fabricant fournit le certificat EK mais que le TPM ne le stocke pas, passer son fichier DER lisible par l'utilisateur à l'installateur, puis à `mysync enroll` :

```sh
curl -fsS https://sync.example.org/install.sh | MYSYNC_EK_CERT=/chemin/prive/ek.der sh
~/.local/bin/mysync enroll --server https://sync.example.org --dir "$HOME/Sync" --ek-cert /chemin/prive/ek.der --invitation-stdin < /chemin/prive/invitation
```

Le client compare ce certificat à la clé EK du TPM ; le serveur vérifie ensuite sa chaîne constructeur. Voir la [procédure AMD et ses limites](docs/device-auth.md#certificat-ek-absent-du-tpm). Ne jamais utiliser un certificat auto-signé comme substitut.

### Appairer l'appareil

L'administrateur crée une invitation propre à chaque appareil et la transmet confidentiellement. Le [guide TPM](docs/device-auth.md#appairage-et-approbation) détaille les commandes serveur et la comparaison d'empreinte.

Sur le client :

```sh
~/.local/bin/mysync enroll --server https://sync.example.org --dir "$HOME/Sync" --invitation-stdin < /chemin/prive/invitation
```

Le client affiche un identifiant et une empreinte. L'administrateur compare cette empreinte avec celle du serveur par un canal fiable, puis approuve l'appareil. Ensuite :

```sh
~/.local/bin/mysync enroll-activate
systemctl --user enable --now mysync.service
sudo loginctl enable-linger "$(id -un)"
```

Sauvegarder les fichiers importants avant la première synchronisation. Le *linger* permet au service utilisateur de démarrer au boot, même sans session ouverte. Pour vérifier :

```sh
~/.local/bin/mysync status
systemctl --user status mysync.service
journalctl --user -u mysync.service -f
```

`~/Sync` est un dossier local normal : on peut l'ajouter aux favoris de Dolphin ou d'un autre gestionnaire de fichiers. `mysync sync`, `mysync trash`, `mysync restore <id>` et `mysync update` restent disponibles en CLI. Le programme contrôle aussi les mises à jour signées automatiquement.

## Documentation

- [Installer et exploiter le serveur, publier les versions, connaître les limites](docs/operations.md)
- [TPM, appairage et récupération](docs/device-auth.md)
- [Corrections de la revue de sécurité](docs/security-review-followup.md)

## Annexe : quelques termes

| Terme | Sens dans MySyncFiles |
| --- | --- |
| **Miroir** | Dossier local synchronisé avec le serveur. Chaque appareil possède le sien. |
| **Invitation** | Secret temporaire donné par l'administrateur pour demander l'appairage d'un appareil. Elle ne donne pas accès aux fichiers à elle seule. |
| **Appairage** | Association d'une clé non exportable du TPM à un appareil, après contrôle et approbation par l'administrateur. |
| **Conflit** | Deux versions concurrentes d'un fichier. Le serveur choisit la version commune ; la version locale écartée est conservée dans `.mysync-conflicts/`. |
| **Version signée** | Version du programme accompagnée d'une signature et d'une empreinte vérifiées avant installation ou mise à jour. |
