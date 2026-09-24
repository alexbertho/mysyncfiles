# MySyncFiles

MySyncFiles synchronise un dossier entre des appareils Linux. Le serveur stocke les fichiers et décide des révisions ; chaque client conserve son miroir local. Une version locale écartée lors d'un conflit reste récupérable dans `.mysync-conflicts/`.

## Commencer

1. [Installer le serveur](install-server.md), configurer son origine HTTPS et ses autorités TPM, puis [publier un client signé](operations.md#publier-un-client-signe).
2. [Installer le client](install-client.md) sur chaque appareil, créer une invitation, comparer son empreinte et approuver l'appairage.
3. Activer le service utilisateur après la première synchronisation et [contrôler son état](troubleshooting.md).

Le serveur n'a pas besoin de TPM. Chaque client a besoin d'un TPM 2.0 et d'un certificat EK constructeur vérifiable. Debian 13 et Arch Linux sont les systèmes clients testés.

## Repères

| Terme | Sens |
| --- | --- |
| Miroir | Dossier local synchronisé avec le serveur. |
| Invitation | Secret temporaire qui permet de demander un appairage, sans donner accès aux fichiers. |
| Appairage | Association d'une clé TPM à un appareil après contrôle et approbation. |
| Conflit | Modification concurrente dont la version locale écartée reste dans `.mysync-conflicts/`. |
| Release signée | Binaire client accompagné d'un manifeste signé et d'une empreinte vérifiée. |

La [vue d'architecture](architecture.md) explique les échanges ; les pages [serveur](server.md) et [client](client.md) détaillent leur fonctionnement. La [sécurité et les limites](security.md) font partie du choix de déploiement : les données sont en clair côté serveur et MySyncFiles ne remplace pas une sauvegarde.
