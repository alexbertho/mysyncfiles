# MySyncFiles

MySyncFiles synchronise un dossier entre appareils Linux. Le serveur conserve les fichiers et arbitre les révisions ; le client préserve les versions locales écartées dans `.mysync-conflicts/`.

> Les données sont en clair sur le serveur et lisibles par son opérateur ou son proxy HTTPS. MySyncFiles n'est pas une sauvegarde et n'a pas encore fait l'objet d'un audit indépendant.

## Démarrage rapide

Il faut Docker Compose et `make` sur le serveur, puis un client Linux x86-64 ou AArch64 avec TPM 2.0 et certificat EK constructeur. Debian 13 et Arch Linux/dérivées sont testés côté client ; le serveur n'a pas besoin de TPM.

**Serveur.** Depuis une copie du dépôt, préparer les dossiers et `deploy/.env` comme indiqué dans le [guide d'installation serveur](docs/install-server.md), puis :

```sh
make install
make start
```

Configurer ensuite le proxy HTTPS et les autorités EK constructeur, puis [publier un client signé](docs/operations.md#publier-un-client-signe). Le serveur ne fournit pas de binaire client prêt à installer tant que cette publication n'a pas eu lieu.

**Client.** Remplacer le domaine d'exemple et installer le client signé dans un terminal :

```sh
curl -fsS --proto '=https' --max-redirs 0 https://sync.example.org/install.sh | sh
```

L'installateur demande la clé publique du serveur, puis affiche un code. Sur le serveur, l'administrateur lance :

```sh
make pair
```

Cette commande affiche la clé publique à transmettre directement au client par un canal fiable. Le client l'enregistre pour vérifier les réponses du serveur, même derrière un proxy TLS. Pour un profil existant, suivre la [migration de la clé serveur](docs/device-auth.md#authenticite-des-reponses-et-migration).

Après comparaison de l'empreinte TPM, le client effectue une première synchronisation et démarre le service s'il n'y a pas de conflit. Le [guide client](docs/install-client.md) couvre la reprise, le cas du certificat EK externe et le parcours manuel. Une première exécution du script suppose que l'origine HTTPS sert le bon script ; la signature protège le binaire téléchargé, pas un script distant compromis.

## Documentation

- [Guide complet et architecture](docs/index.md)
- [Installation du serveur](docs/install-server.md) et [du client](docs/install-client.md)
- [Sécurité et limites](docs/security.md), [déploiement](docs/operations.md) et [dépannage](docs/troubleshooting.md)

Pour prévisualiser la documentation localement : `make docs` puis ouvrir `http://127.0.0.1:8000`. `make docs-stop` l'arrête ; `make docs-check` vérifie sa construction. Le service de documentation est optionnel et ne démarre pas le serveur.

Le [guide de déploiement](docs/operations.md#publier-la-documentation) explique comment publier le site statique à `/docs/` sur la même origine HTTPS que l'API.
