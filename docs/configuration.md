# Configuration

## Serveur

Copier `deploy/.env.example` vers `deploy/.env`, puis renseigner les valeurs propres à l'hôte. Ce fichier est ignoré par Git.

| Variable | Rôle |
| --- | --- |
| `MYSYNC_UID`, `MYSYNC_GID` | Identité du processus serveur et propriétaire attendu des données. |
| `MYSYNC_DATA_DIR` | Chemin absolu du stockage privé : SQLite et fichiers. |
| `MYSYNC_RELEASES_DIR` | Chemin absolu des releases clientes, monté en lecture seule dans le conteneur. |

Créer ces deux dossiers séparément avant `make start`. La clé privée de signature et les invitations doivent rester hors du répertoire des releases. L'[installation serveur](install-server.md#preparer-le-stockage) donne un exemple complet.

La commande `device auth-configure` enregistre dans SQLite l'origine publique HTTPS exacte (`--public-url`) et les racines EK constructeur vérifiées (`--ek-roots`). Elles ne sont pas déduites des en-têtes du proxy et aucune racine de test n'est installée par défaut. La [procédure TPM](device-auth.md#configuration-du-serveur) donne la commande complète. Le proxy doit préserver le corps et les en-têtes d'authentification, sans mise en cache des routes protégées.

## Client

`mysync enroll --server URL --dir DOSSIER` crée la configuration privée du client après attestation TPM. Son chemin par défaut est `$XDG_CONFIG_HOME/mysync/config.json`, ou `$HOME/.config/mysync/config.json` si `XDG_CONFIG_HOME` n'est pas défini. L'option globale `--config CHEMIN` permet d'utiliser un autre fichier. Le fichier d'état et le fichier d'appairage en attente sont placés à côté, hors du miroir.

Le certificat EK externe éventuel est un fichier DER fourni explicitement à l'installateur (`MYSYNC_EK_CERT`) et à `mysync enroll --ek-cert`. Les certificats intermédiaires vérifiés peuvent être passés à `--ek-chain`. Ni l'un ni l'autre ne modifient automatiquement la confiance du serveur. Voir le [guide client](install-client.md) et le [guide TPM](device-auth.md#prerequis-client).

Le service utilisateur installé démarre `mysync daemon` avec la configuration par défaut. Si `--config` est utilisé pour l'appairage, adapter l'unité utilisateur avant de l'activer afin qu'elle pointe vers le même fichier.
