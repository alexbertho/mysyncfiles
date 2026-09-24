# Architecture

MySyncFiles a deux composants : un serveur qui stocke les fichiers et tranche les révisions, et un client par appareil qui synchronise un dossier local. Le client peut effectuer un passage avec `mysync sync` ou surveiller le miroir en continu avec un service systemd utilisateur.

```text
Miroir local et TPM ── client mysync ── HTTPS ── proxy TLS ── serveur
                                                          │
                                            SQLite + fichiers + releases
```

Le serveur n'a pas de TPM. Le proxy transmet les requêtes mais ne décide ni de l'identité des appareils ni du contenu des fichiers. Les données traversant un proxy qui termine TLS y sont lisibles.

## Cycle d'un fichier

1. Le client lit le manifeste du serveur, puis compare ses révisions connues à l'état de son miroir.
2. Il envoie les modifications locales avec la révision de base observée. Les gros fichiers sont transférés par blocs d'au plus 8 Mio.
3. Le serveur accepte ou refuse l'opération selon sa révision courante et attribue la nouvelle révision.
4. Le client télécharge les changements distants. Si une version locale serait écartée, il la place dans `.mysync-conflicts/` avant de remplacer le fichier du miroir.

Une suppression apparaît comme une révision et peut être restaurée depuis la corbeille serveur pendant 30 jours. Un écrasement ordinaire n'a pas d'historique restaurable. Les dossiers vides et les liens symboliques ne sont pas synchronisés. Voir le [fonctionnement du client](client.md) et les [limites](security.md).

## Identité et mises à jour

Chaque appareil crée une clé non exportable dans son TPM. L'administrateur fournit une invitation, le serveur vérifie la chaîne EK constructeur et l'appareil doit être approuvé après comparaison de l'empreinte. Les requêtes suivantes portent une preuve TPM fraîche. Voir le [guide d'identité](device-auth.md).

Le serveur distribue aussi l'installateur et les releases du client. Le manifeste de release est signé ; le client vérifie cette signature et le hash du binaire avant installation ou mise à jour. La clé privée de signature reste hors du serveur et des fichiers servis. Voir la [publication](operations.md#publier-un-client-signe).
