# Politique de confidentialité de PixelGuard

Cette politique décrit PixelGuard 0.2.0, y compris son intégration facultative avec VirusTotal.

## Analyse locale du suivi

PixelGuard lit le HTML du message affiché et les métadonnées de base de l'expéditeur, comme le domaine de l'en-tête From, afin de repérer d'éventuels pixels de suivi, liens de suivi et images externes. L'analyse du suivi s'effectue localement. PixelGuard ne modifie pas les messages enregistrés et ne contourne pas les contrôles de contenu distant de Thunderbird.

Pour le panneau de consultation facultative, PixelGuard lit également le HTML ou le texte brut du message affiché afin de répertorier les liens HTTP(S), et récupère les noms et les tailles des pièces jointes. Il ne visite pas ces liens et ne suit pas leurs redirections. Lorsqu'une pièce jointe est sélectionnée pour une consultation, ses octets sont lus par l'intermédiaire de Thunderbird et une empreinte SHA-256 est calculée localement. Dans le cadre de son fonctionnement normal, Thunderbird peut devoir récupérer les données du message ou de la pièce jointe auprès du service de messagerie de l'utilisateur. PixelGuard n'exécute ni ne décompresse la pièce jointe. La limite initiale de taille par pièce jointe est de 50 MiB.

## Requêtes facultatives à VirusTotal

L'intégration est désactivée par défaut. Pour l'activer, vous devez saisir votre propre clé API VirusTotal, accepter l'explication du partage de données et accorder les autorisations facultatives. L'ouverture d'un message ou du panneau contextuel et l'enregistrement de la clé ne déclenchent aucune consultation de VirusTotal.

Uniquement lorsque vous demandez une consultation, PixelGuard envoie directement à VirusTotal, via HTTPS, les données suivantes :

- Le domaine sélectionné, ou l'URL complète exacte affichée dans un aperçu et que vous confirmez explicitement.
- Pour une pièce jointe, son empreinte SHA-256 à la place de son contenu ou de son nom de fichier.
- Votre clé API VirusTotal dans un en-tête d'authentification.

VirusTotal reçoit également les informations de connexion habituelles, comme votre adresse IP. Une empreinte ne révèle pas les octets du fichier, mais elle peut identifier un fichier déjà connu de VirusTotal. Une URL peut contenir des informations personnelles, des jetons d'accès ou d'autres identifiants privés. Privilégiez la consultation du domaine si vous ne souhaitez pas divulguer l'adresse complète.

PixelGuard demande des informations de contexte existantes au moyen de l'API du widget VT Augment. Il ne téléverse ni le corps des messages ni les octets des pièces jointes, ne soumet aucune URL à une nouvelle analyse et ne demande aucune réanalyse. Il n'utilise ni proxy ni service de télémétrie exploités par le développeur. Les résultats de VirusTotal apportent un contexte facultatif et ne modifient pas les classifications, alertes ou compteurs de suivi de PixelGuard.

L'ouverture du rapport officiel charge une page web VirusTotal dans un onglet Thunderbird distinct ou dans votre navigateur par défaut. Cette page est fournie par VirusTotal, avec ses propres cookies, requêtes et politiques de conservation des données et de compte ; les actions que vous y effectuez se situent en dehors du processus de consultation de PixelGuard. Consultez les [informations de confidentialité de VirusTotal](https://docs.virustotal.com/docs/privacy-policy), les [conditions applicables](https://docs.virustotal.com/docs/terms-of-service) et les [conditions de l'API](https://docs.virustotal.com/reference/public-vs-premium-api).

## Stockage et conservation

- Les préférences et les compteurs de détection sont enregistrés dans le stockage local de l'extension dans Thunderbird. PixelGuard ne les synchronise pas et ne les transmet pas à son développeur.
- Les horodatages des requêtes sont enregistrés localement pour limiter les appels à l'API à quatre par minute et à 500 sur une période glissante de 24 heures, y compris après un redémarrage. Ils ne contiennent aucun domaine, URL, empreinte ou nom de fichier. Les entrées de plus de 24 heures sont supprimées lors de la réservation de la requête suivante.
- Si vous la fournissez, la clé API VirusTotal est enregistrée séparément des paramètres généraux dans `browser.storage.local`. Ce stockage n'est pas un coffre-fort chiffré pour les identifiants. Un accès à votre profil Thunderbird, à ses sauvegardes ou à votre appareil peut exposer les données stockées localement. PixelGuard n'inclut pas la clé dans les exports de paramètres, les réponses de l'API aux scripts de messages, les journaux ou le paquet de l'extension.
- L'inventaire VirusTotal, les résultats des consultations et les URL temporaires des rapports restent en mémoire pendant la session du message ; ils ne sont pas enregistrés dans un historique de consultations. Ils sont effacés lorsque le message change ou que son onglet se ferme, lorsque l'intégration est désactivée ou lorsque la clé change. Les opérations en attente ne peuvent pas restaurer des résultats dans une session invalidée.
- Les onglets VirusTotal déjà ouverts restent ouverts indépendamment. Vider la mémoire de PixelGuard ne révoque pas une URL temporaire de rapport et n'efface ni l'historique du navigateur, ni la sortie de la console, ni les données déjà reçues par VirusTotal.
- Le mode de débogage est désactivé par défaut. Lorsqu'il est activé, l'analyseur de suivi existant peut consigner ses résultats, y compris les URL complètes des messages, dans la console locale de Thunderbird. Les clés VirusTotal et les jetons temporaires des rapports ne sont pas consignés. La conservation et les exports de la console sont contrôlés par Thunderbird et l'utilisateur.

## Vos moyens de contrôle

Dans les paramètres de PixelGuard, vous pouvez désactiver VirusTotal, remplacer la clé ou la supprimer. La désactivation empêche les nouvelles consultations et annule les requêtes en attente ; la suppression de la clé efface également la clé enregistrée. La révocation des autorisations facultatives empêche toute nouvelle consultation. La désactivation de l'intégration ne permet pas de retirer les données déjà transmises. Vous pouvez désactiver ou supprimer PixelGuard depuis le gestionnaire de modules complémentaires de Thunderbird.

## Finalité des autorisations

- `messagesRead` : accéder au message affiché et à ses métadonnées, répertorier ses pièces jointes et lire une pièce jointe sélectionnée pour calculer son empreinte localement.
- `messagesModify` : enregistrer les scripts d'affichage des messages de PixelGuard et afficher sa bannière dans le message. PixelGuard ne modifie pas les courriels et n'enregistre aucune modification de ceux-ci.
- `storage` : enregistrer les préférences locales, les compteurs et la clé API facultative.
- `sensitiveDataUpload`, facultative : informer de l'indicateur sélectionné envoyé au service de consultation tiers et autoriser son envoi.
- `https://www.virustotal.com/*`, facultative : effectuer la requête HTTPS authentifiée vers le point de terminaison fixe de VirusTotal.

## Contact

Adresse e-mail : hello@enriqueite.com
