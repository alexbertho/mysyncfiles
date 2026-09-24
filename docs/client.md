# Fonctionnement du client

`mysync` synchronise un miroir local configuré lors de l'appairage. `mysync sync` lance un passage ; `mysync daemon` surveille les changements et relance périodiquement la synchronisation. Le service `mysync.service` est un service systemd **utilisateur**, activé seulement après l'approbation de l'appareil.

## Réconciliation et conflits

Le client compare le manifeste serveur, son état local et le contenu du miroir. Le serveur tranche les révisions ; lors d'une divergence, les données locales écartées restent dans `.mysync-conflicts/`. `.mysync-staging/` sert aux téléchargements temporaires. Ces dossiers restent locaux et ne sont pas synchronisés.

Les opérations sur le miroir refusent les liens symboliques et restent confinées par des descripteurs de répertoire, même si l'arborescence change pendant un transfert. Le client continue par interrogation toutes les 15 secondes si la surveillance native échoue. Les noms non UTF-8, dossiers vides, permissions et attributs étendus ne sont pas synchronisés ; un renommage équivaut à une suppression puis un ajout.

## Commandes utiles

| Commande | Effet |
| --- | --- |
| `mysync status` | Affiche les comptes locaux/distants et les conflits. |
| `mysync sync` | Lance un passage de synchronisation. |
| `mysync trash` | Liste les suppressions restaurables du serveur. |
| `mysync restore ID` | Restaure un élément de la corbeille et synchronise. |
| `mysync update` | Cherche et installe une version cliente signée plus récente. |

La configuration et l'état du client résident hors du miroir, dans le répertoire de configuration utilisateur. Une clé TPM copiée sur un autre appareil ne permet pas d'utiliser l'identité. Voir la [configuration](configuration.md) et les [limites de cette garantie](device-auth.md#garanties-et-limites).

## Service et mises à jour

Après [l'activation de l'appairage](install-client.md#activer-la-synchronisation-manuelle), `systemctl --user` pilote le service. Le démon contrôle les mises à jour au démarrage puis toutes les six heures ; une erreur de mise à jour ne bloque pas la synchronisation. Le manifeste signé, la cible, la taille et le SHA-256 sont contrôlés avant le remplacement atomique de `~/.local/bin/mysync`. La publication et l'installation locale sont verrouillées pour éviter une rétrogradation concurrente. Une installation sous `/usr/bin` n'est pas remplacée automatiquement.
