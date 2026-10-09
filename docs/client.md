# Fonctionnement du client

`mysync` synchronise un miroir local configuré lors de l'appairage. `mysync sync` lance un passage ; `mysync daemon --all` surveille les changements des dossiers des profils enregistrés et relance périodiquement la synchronisation. Le service `mysync.service` est un service systemd **utilisateur**, activé seulement après l'approbation de l'appareil.

## Réconciliation et conflits

Le manifeste et les réponses de mutations sont vérifiés avec la clé serveur épinglée, puis les téléchargements sont comparés aux hashes authentifiés. Une signature absente ou invalide arrête la synchronisation avant d'appliquer les métadonnées concernées. Les copies déplacées dont la taille, l'identité, les dates de modification ou de changement varient pendant le hash restent conservées, même si le digest correspond encore à une lecture antérieure.

La surveillance ignore les ouvertures et lectures du scanner ainsi que l'entretien des dossiers `.mysync-staging/` et `.mysync-conflicts/`. Les créations, écritures, suppressions et renommages dans le miroir continuent de déclencher une passe ; déplacer une copie de conflit vers le miroir déclenche également une synchronisation.

Le client compare le manifeste serveur, son état local et le contenu du miroir. Le serveur tranche les révisions ; lors d'une divergence, les données locales écartées restent dans `.mysync-conflicts/`. `.mysync-staging/` sert aux téléchargements temporaires. Ces dossiers restent locaux et ne sont pas synchronisés.

Les opérations sur le miroir refusent les liens symboliques et restent confinées par des descripteurs de répertoire, même si l'arborescence change pendant un transfert. Le client continue par interrogation toutes les 15 secondes si la surveillance native échoue. Les noms non UTF-8, dossiers vides, permissions et attributs étendus ne sont pas synchronisés ; un renommage équivaut à une suppression puis un ajout.

## Commandes utiles

La page `/status` du serveur permet aussi une [vérification de présence locale](web-status.md), activée par défaut depuis la version 0.3.8 et désactivable à l’installation ou en commande. Elle affiche un statut léger, sans compte ni lecture de fichiers.

| Commande | Effet |
| --- | --- |
| `mysync status` | Affiche les comptes locaux/distants et les conflits. |
| `mysync sync` | Lance un passage de synchronisation. |
| `mysync trash` | Liste les suppressions restaurables du serveur. |
| `mysync restore ID` | Restaure un élément de la corbeille et synchronise. |
| `mysync update` | Cherche et installe une version cliente signée plus récente. |
| `mysync web-status status` | Affiche le réglage local de présence navigateur. |
| `mysync web-status enable` / `disable` | Active ou désactive ce réglage ; relancer le daemon pour l’appliquer. |
| `mysync web-files status` | Affiche l’autorisation locale de lecture web, désactivée par défaut. |
| `mysync web-files enable` / `disable` | Autorise ou refuse les nouvelles sessions de lecture dans l’[explorateur Atlas](web-files.md) ; relancer le daemon. |

La configuration et l'état du client résident hors du miroir, dans le répertoire de configuration utilisateur. Une clé TPM copiée sur un autre appareil ne permet pas d'utiliser l'identité. Voir la [configuration](configuration.md) et les [limites de cette garantie](device-auth.md#garanties-et-limites).

## Service et mises à jour

Après [l'activation de l'appairage](install-client.md#activer-la-synchronisation-manuelle), `systemctl --user` pilote le service. Le démon contrôle les mises à jour au démarrage puis toutes les six heures ; une erreur de mise à jour ne bloque pas la synchronisation. Le manifeste signé, la cible, la taille et le SHA-256 sont contrôlés avant le remplacement atomique de `~/.local/bin/mysync`. La publication et l'installation locale sont verrouillées pour éviter une rétrogradation concurrente. Une installation sous `/usr/bin` n'est pas remplacée automatiquement.

`mysync update` installe uniquement une release signée dont la version est supérieure à celle du client. En l'absence de mise à jour, il affiche les deux versions comparées. Redéployer le serveur ne publie pas de nouveau client : cette publication doit être faite par l'administrateur. Après une mise à jour manuelle, relancer le daemon ou le service utilisateur déjà actif pour charger le nouveau binaire. Le profil et l'identité TPM sont conservés ; les options désactivées, comme `web_status_enabled`, restent désactivées.
