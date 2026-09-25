# Sécurité et limites

MySyncFiles exige HTTPS pour les clients et une identité TPM approuvée pour accéder aux fichiers. L'appairage vérifie une chaîne EK constructeur explicitement approuvée et une preuve de possession de la clé TPM ; les requêtes suivantes portent une preuve fraîche liée à leur contenu. Les détails et limites matérielles sont décrits dans le [guide TPM](device-auth.md).

## Données et sauvegardes

Les fichiers et SQLite sont en clair sur le serveur. L'opérateur du serveur et un proxy qui termine TLS, notamment Cloudflare, peuvent les lire. Il n'y a **pas** de chiffrement de bout en bout. Une suppression reste en corbeille 30 jours, mais un écrasement ordinaire n'a pas d'historique restaurable. MySyncFiles n'est **pas** une sauvegarde : garder des sauvegardes indépendantes, idéalement chiffrées hors site, et tester leur restauration.

Le serveur arbitre les révisions ; le client conserve dans `.mysync-conflicts/` les versions locales écartées. Les liens symboliques sont refusés sur le miroir, et les chemins restent confinés pendant les transferts. Les détails de synchronisation sont dans l'[architecture](architecture.md) et le [fonctionnement du client](client.md).

## Distribution et exploitation

Les réponses de l'API sont signées par une clé serveur Ed25519 épinglée lors de l'installation et liée à chaque requête fraîche. Les tailles et hashes de fichiers sont ainsi authentifiés indépendamment du proxy TLS ; les téléchargements doivent correspondre à ces métadonnées. La clé publique est transmise directement par l'administrateur. Voir le [protocole et la migration des profils existants](device-auth.md#authenticite-des-reponses-et-migration).

L'installateur et les mises à jour vérifient le manifeste signé et le hash du binaire. La première récupération du script d'installation exige néanmoins une origine HTTPS de confiance : la signature ne couvre pas un script distant compromis. Garder la clé privée de signature hors du serveur et du répertoire de releases. Les codes d'appairage, invitations manuelles, configurations clientes et données SQLite restent privés.

Le proxy HTTPS n'est pas une autorité de confiance pour les fichiers ; il doit transmettre les requêtes sans modification ni cache des routes authentifiées. Le serveur borne les corps, réponses et transferts, mais ne dispose pas de quota global. Les listes trop volumineuses peuvent faire échouer une synchronisation ; aucun audit indépendant n'a encore été réalisé. Le [suivi de la revue de sécurité](security-review-followup.md) détaille les protections et les limites restantes.
