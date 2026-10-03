# Explorateur web Atlas

Ouvrir `https://sync.example.com/files` (ou la racine `/` du serveur) pour consulter l’espace synchronisé. Atlas permet de parcourir les dossiers, rechercher par nom ou chemin, consulter les détails et télécharger des fichiers. L’interface est **en lecture seule** : elle ne modifie, ne supprime et ne restaure aucun fichier.

Le menu latéral se masque entièrement avec le bouton en haut à gauche. Le bouton lune/soleil en haut à droite change le thème. Ces deux préférences sont conservées dans le navigateur ; les noms et le contenu des fichiers ne sont pas enregistrés dans le stockage local de la page.

L’interface est constituée de fichiers HTML, CSS et JavaScript natifs dans `web/`, sans framework ni compilation frontend. Le serveur les lit à chaque requête. Avec Docker Compose, ce dossier est monté en lecture seule dans le conteneur : modifier `web/index.html`, `web/status.css` ou les scripts, puis actualiser le navigateur suffit. Voir [modifier l’interface à chaud](operations.md#modifier-linterface-web-a-chaud) pour la configuration et la mise en place initiale.

## Autoriser la lecture

Le PC Linux du navigateur doit disposer du client **0.3.10 ou ultérieur**, appairé et approuvé sur ce serveur. Le client 0.3.9 publié sait vérifier `/status`, mais ne prend pas en charge `files.read` ni `mysync web-files`. Le déploiement du serveur ne met pas à jour les clients : leur distribution passe toujours par une release signée publiée séparément.

L’autorisation de lire les fichiers est **désactivée par défaut**, y compris pour les profils existants. Elle est distincte de la présence locale :

```sh
mysync web-files status
mysync web-files enable
```

Si le daemon verrouille le profil, l’arrêter avant de changer ce réglage. Relancer ensuite le daemon ou le service utilisateur déjà installé et activé. Le pont local doit aussi être actif (`mysync web-status status`, puis `mysync web-status enable` si nécessaire).

Dans Atlas, cliquer sur **Vérifier cet appareil** et accepter l’accès local demandé par le navigateur. La page ouvre une session de lecture de **30 minutes** lorsque le serveur confirme la preuve TPM et le scope `files.read`. L’autorisation `status.read` ne suffit pas. Les conditions et limites du [pont loopback](web-status.md#acces-local-et-erreurs) restent applicables.

Tous les appareils approuvés consultent le **même espace global de fichiers**. L’approbation ne crée ni compte utilisateur ni dossier privé par appareil. Le client local autorise l’origine configurée ; cette autorisation ne distingue pas les utilisateurs Linux ou les navigateurs exécutés sur ce PC.

## Parcourir et télécharger

Les dossiers sont déduits des chemins des fichiers vivants ; les dossiers vides et les entrées supprimées ne sont pas présentés. Cliquer sur un dossier pour l’ouvrir, et sur le fil d’Ariane pour remonter. La recherche couvre tout l’espace, même lorsqu’elle est lancée depuis un sous-dossier. Les caractères `%` et `_` sont recherchés littéralement.

La colonne **Taille** affiche pour chaque dossier la somme des tailles de tous ses fichiers, sous-dossiers compris, hors fichiers supprimés. Il s’agit de la taille logique des fichiers, pas de l’espace disque physique occupé par le serveur. Le calcul utilise les métadonnées SQLite dans la requête de liste existante : aucun fichier n’est ouvert pour mesurer sa taille et aucune requête supplémentaire par dossier n’est nécessaire. Le parcours d’un sous-dossier utilise l’index des chemins pour limiter la lecture à son contenu.

La colonne **Dernière modification** affiche la date d’enregistrement de la version courante sur le serveur, dans le fuseau horaire du navigateur. Elle ne correspond pas nécessairement à la date de modification du fichier sur le PC. Pour un dossier, elle indique la date la plus récente parmi ses fichiers présents, sous-dossiers compris ; les fichiers supprimés sont exclus. Cette date est calculée avec la taille dans la même requête SQLite. Si le serveur ne fournit pas encore cette information, un tiret est affiché.

Chaque ligne de fichier propose un menu **…** : **Télécharger**, **Voir les détails**, **Copier le chemin**. Un clic sur son nom ouvre aussi le panneau latéral. Celui-ci affiche le nom et le chemin complets, la taille, la date avec les secondes et le fuseau horaire, la révision et l’empreinte SHA-256 complète. Les noms trop longs sont seulement tronqués dans la liste.

La liste affiche au plus **200 éléments par page**, dossiers en premier, dans l’ordre des chemins. Utiliser les boutons de pagination pour continuer. L’icône **Actualiser les fichiers**, près de la recherche, met à jour la page courante en conservant les détails ouverts si le fichier est encore présent ; les changements du serveur ne sont pas sondés en permanence. Les lignes restent affichées pendant une requête, puis les résultats et le chemin sont remplacés ensemble. Une erreur de connexion conserve la liste précédente et permet de réessayer la navigation demandée avec l’icône d’actualisation. Le navigateur masque les données affichées à l’expiration ou à la déconnexion, et revérifie l’autorisation avant de restaurer une page depuis son historique.

Le téléchargement utilise des blocs d’au plus **8 Mio**, liés à une révision précise. Si le fichier change ou est supprimé pendant le transfert, actualiser la liste et recommencer. Le navigateur compare l’empreinte SHA-256 du contenu reçu à celle des métadonnées avant de lancer l’enregistrement. Le message **Téléchargement lancé** confirme la remise au navigateur, pas l’écriture finale sur le disque.

Cette première version limite les téléchargements web à **256 Mio par fichier**, avec un seul transfert à la fois, afin de borner la mémoire utilisée pour l’assemblage et la vérification. Les fichiers plus volumineux restent accessibles par la synchronisation Linux. Le bouton **Annuler** interrompt la préparation du téléchargement.

## Expiration et révocation

**Déconnexion** supprime la session sur le serveur, ses challenges et son autorisation de lecture. Les autres onglets ouverts sur la même origine effacent aussi leur affichage lorsqu’ils reçoivent cette déconnexion. Après 30 minutes, une nouvelle vérification explicite est nécessaire ; consulter un dossier ne prolonge pas la session.

```sh
mysync web-files disable
```

Après redémarrage du daemon, cette commande refuse les **nouvelles** preuves de lecture. Les sessions déjà accordées restent valables jusqu’à leur expiration ou leur déconnexion. La révocation administrative de l’appareil invalide immédiatement les prochaines requêtes de métadonnées et de blocs. Elle ne retire pas les fichiers déjà téléchargés, ni un bloc déjà remis au navigateur. Un onglet resté immobile peut conserver son affichage jusqu’à sa prochaine requête ou l’expiration locale.

Les vues de vérification, de permission refusée et de session expirée n’affichent aucun nom de fichier. Si la permission locale est refusée, ouvrir les permissions du site dans la barre d’adresse du navigateur, autoriser l’accès au réseau local et réessayer. Si la lecture est désactivée dans le client, la page indique comment l’activer.

Si `/status` reconnaît l’appareil mais que `/files` affiche « Vérification locale refusée », vérifier que `mysync web-files status` existe dans le client installé. Un ancien client peut synchroniser et prouver sa présence tout en refusant les demandes de lecture web. Utiliser un client incluant Atlas, activer `mysync web-files enable`, puis relancer le service déjà installé. Si la commande existe et que la lecture est activée, vérifier que le daemon en cours a bien été relancé, qu’il utilise le même serveur et que l’horloge du PC est correcte. Le navigateur consulte toujours le serveur avant d’accorder l’accès, même si la réponse locale indique une erreur.

## Protocole et limites de confiance

La session utilise le cookie distinct `__Host-mysync-files`, `Secure`, `HttpOnly`, `SameSite=Strict`, avec `Path=/`. Seul son hash est enregistré sur le serveur. La phase anonyme expire après cinq minutes ; une preuve `files.read` valide prolonge l’autorisation jusqu’à 30 minutes après sa réception. Le cookie peut vivre 35 minutes pour couvrir ces deux phases, mais sa présence seule n’accorde aucun accès. Les sessions et challenges partagent les quotas bornés du [protocole de présence](web-status.md#protocole-et-limites).

Le ticket signé lie le scope, l’origine, l’audience, la session, l’appareil attendu le cas échéant et les dates. Le client contrôle le consentement local avant de signer une preuve avec le TPM. Le serveur consomme le challenge une seule fois, puis contrôle l’appairage, l’approbation, la révocation et l’expiration à chaque lecture de métadonnées ou de bloc. Les routes de lecture web n’autorisent aucune mutation. Les réponses sont `no-store`, les erreurs sont génériques et les libellés sont insérés comme texte.

Comme pour la page de statut, le navigateur doit recevoir un HTML et un JavaScript de confiance. Un site compromis ou un proxy capable de remplacer l’application web peut altérer son affichage ; la vérification SHA-256 dans cette application ne constitue pas une authentification indépendante du code servi. Le client Linux conserve sa vérification des réponses signées avec la clé serveur épinglée. Atlas n’est ni un chiffrement de bout en bout ni une sauvegarde : les fichiers sont en clair sur le serveur et les écrasements ordinaires n’ont pas d’historique restaurable.

## Validation développeur

`make test` valide les sessions, les scopes, les chemins, la pagination, les limites de blocs, la révocation et le consentement local, ainsi qu’un échange de lecture avec un TPM simulé. La suite navigateur utilise les mêmes outils isolés que la [suite de présence](web-status.md#validation-developpeur) :

```sh
NODE_PATH=/chemin/vers/node_modules node tests/web_files_browser.cjs
```

Elle couvre les thèmes, la navigation repliable, les dossiers, les menus au clavier, les noms longs, la recherche, la pagination, les états d’accès, l’expiration, les téléchargements et leur intégrité. Le backend de cette suite est simulé ; l’autorité cryptographique est vérifiée par les tests Rust. Les icônes Phosphor sont distribuées avec leur licence MIT dans `web/atlas-icons.LICENSE` ; la marque provient des références Atlas fournies dans `design/atlas`.
