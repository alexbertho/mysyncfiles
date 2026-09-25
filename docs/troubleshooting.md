# Dépannage

Commencer par vérifier le service concerné et conserver les messages d'erreur exacts :

```sh
make logs
~/.local/bin/mysync status
systemctl --user status mysync.service
journalctl --user -u mysync.service -f
```

`make logs` se lance sur l'hôte serveur depuis le dépôt ; les autres commandes se lancent sur le client. Ne pas publier les codes d'appairage, invitations, configurations privées, empreintes EK complètes ou journaux contenant des secrets.

| Symptôme | Vérification et suite |
| --- | --- |
| `make install` réclame `deploy/.env` | Copier et compléter `deploy/.env.example`, puis créer les dossiers avec les droits correspondant à l'UID/GID. Voir l'[installation serveur](install-server.md). |
| Le serveur ne peut pas ouvrir `/data` ou `/releases` | Contrôler les chemins absolus, leur existence et leurs permissions dans `deploy/.env`. Voir la [configuration](configuration.md). |
| `/install.sh` répond 503 | Configurer l'origine publique avec `device auth-configure`. Voir le [guide TPM](device-auth.md#configuration-du-serveur). |
| L'installateur ne trouve pas de release | Publier une release signée pour l'architecture du client ; le serveur ne la fabrique pas au démarrage. Voir la [publication](operations.md#publier-un-client-signe). |
| Le client refuse le TPM ou son certificat | Vérifier `/dev/tpmrm0`, les droits utilisateur, le certificat EK constructeur et, si nécessaire, `--ek-cert`. Voir les [prérequis TPM](device-auth.md#prerequis-client). |
| `mysync setup` attend le serveur | Lancer `make pair`, saisir le code affiché sur le client et vérifier que l'origine HTTPS répond. Si le code a expiré ou a été annulé, relancer `mysync setup` pour en générer un nouveau. |
| `mysync setup` attend l'approbation | Dans `make pair`, comparer l'empreinte TPM complète avec celle du client, puis confirmer. En cas d'interruption, relancer `make pair` avec le même nom et le même code. |
| L'appairage manuel attend l'approbation | Comparer l'empreinte reçue du client avec `device pending`, approuver la même identité, puis lancer `mysync enroll-activate`. Voir le [parcours manuel](install-client.md#parcours-manuel-avec-invitation). |
| Le service reste arrêté après la première synchronisation | Examiner les fichiers de `.mysync-conflicts/` et les erreurs affichées, puis relancer `mysync setup` ; activer le service seulement après une vérification sans conflit. |
| Erreurs de preuve ou d'URL après mise en place du proxy | Vérifier l'origine HTTPS exacte, les horloges et la transmission intacte de la méthode, de l'URL, du corps et des en-têtes. Voir le [protocole](device-auth.md#protocole-des-requetes). |
| Des changements ne remontent pas immédiatement | Lancer `mysync sync` et examiner les conflits locaux ; si la surveillance échoue, le client interroge le miroir toutes les 15 secondes. Voir le [client](client.md). |

Après perte du TPM ou de la configuration, suivre la [révocation et la récupération](device-auth.md#revocation-et-recuperation). Sauvegarder le miroir avant un nouvel appairage ; ne pas effacer le TPM pour résoudre une erreur d'accès.
