# Fonctionnement du serveur

`mysync-server` expose une API HTTP sur `127.0.0.1:8484` côté hôte Docker ; un proxy assure l'accès HTTPS public. Le conteneur fonctionne sans privilège, avec un système de fichiers racine en lecture seule, `/tmp` privé en mémoire et deux montages : les données privées en écriture et les releases publiques en lecture seule. Le serveur n'utilise pas de TPM local.

## Stockage et révisions

Le répertoire de données contient la base SQLite, les blobs des fichiers et les transferts temporaires. SQLite conserve les métadonnées, les révisions et l'état des appareils. Un seul processus serveur doit utiliser cette base à la fois. Les chemins soumis à l'API sont vérifiés ; les collisions fichier/répertoire sont refusées.

Le serveur est l'autorité sur les révisions. Une requête qui part d'une ancienne révision ne remplace pas silencieusement la version courante ; le client doit résoudre la divergence et conserver la version locale écartée. Les suppressions sont gardées en corbeille pendant 30 jours, tandis que les écrasements ordinaires ne sont pas restaurables. Prévoir des [sauvegardes indépendantes](operations.md#sauvegardes-et-maintenance).

## Routes et administration

`/v1/health` donne un contrôle local de disponibilité. `/install.sh` sert le script client après configuration de l'origine publique. `/v1/updates/…` sert les releases signées présentes dans le montage dédié. Les routes de synchronisation exigent une session et une preuve TPM liée à la requête. Les réponses et transferts sont bornés, et l'API ne suit aucune redirection HTTP.

Les opérations d'administration des appareils (`device auth-configure`, `pair`, `invite`, `pending`, `approve`, `revoke`) s'exécutent localement via `mysync-server` dans le conteneur. `make pair` guide l'appairage courant ; il n'existe pas de route HTTP pour approuver un appareil. Voir la [configuration](configuration.md) et l'[appairage](device-auth.md#appairage-et-approbation).

## Limites opérationnelles

Chaque composant de chemin est limité à 255 octets UTF-8 ; les chemins relatifs atteignent au plus 4 096 octets. Le serveur refuse les collisions entre fichier et répertoire. Les listes de manifeste et de corbeille sont limitées à 32 Mio, les autres réponses JSON à 64 Kio. Elles ne sont pas paginées : une liste trop grande échoue sans être tronquée. Les transferts ont des limites de taille et de durée, avec vérification du hash ; les corps des requêtes signées sont bornés à 8 Mio.

Il n'y a pas de quota global de stockage. Prévoir une surveillance du disque et des limites de connexion au proxy. Les [contraintes de sécurité](security.md) et les [détails du protocole](device-auth.md#protocole-des-requetes) donnent le contexte de ces limites.
