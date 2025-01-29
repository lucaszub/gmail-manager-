# Gmail Categorization Azure Function

Ce projet implémente une fonction Azure qui se connecte à un compte Gmail, récupère les derniers emails, et les catégorise en utilisant l'API OpenAI pour déterminer la catégorie de chaque message (par exemple : "Urgent", "Finance", "Rendez-vous", etc.). Une fois la catégorie déterminée, la fonction applique l'étiquette correspondante à l'email dans Gmail.

## Fonctionnalités

- **Récupération des emails** : L'application se connecte à Gmail pour récupérer les derniers emails (limités à 20).
- **Nettoyage des emails** : Le corps des emails est nettoyé pour enlever les mots fréquents et les liens.
- **Catégorisation des emails** : Les emails sont catégorisés selon leur sujet, expéditeur et contenu à l'aide de l'API OpenAI.
- **Création et application d'étiquettes** : Les étiquettes sont créées dans Gmail si elles n'existent pas et sont appliquées aux emails en fonction de leur catégorie.
  
## Prérequis

Avant de déployer cette fonction, assurez-vous que vous avez les éléments suivants configurés :

- **Azure** : Un compte Azure pour déployer une Azure Function.
- **Gmail API** : Un projet Google Cloud avec l'API Gmail activée et les credentials OAuth2 générés.
- **Key Vault Azure** : Un Key Vault Azure pour stocker les secrets, notamment les clés API (OpenAI et Gmail).
- **API OpenAI** : Un compte OpenAI et une clé API pour interagir avec le modèle GPT-3.5.

## Déploiement

1. **Configurer les secrets dans Azure Key Vault** :
    - `OPENAI-API-KEY` : Clé API pour l'OpenAI.
    - `GMAIL-CREDENTIALS` : Informations d'identification OAuth2 pour accéder aux emails Gmail.
    - `token` : Token d'authentification de Gmail.

2. **Déployer sur Azure** :
   - Créez une Azure Function avec une HTTP trigger.
   - Téléchargez ce code dans la fonction Azure.
   - Assurez-vous que l'identity managée Azure est correctement configurée pour accéder au Key Vault.

## Utilisation

Lorsque la fonction est appelée via un HTTP request, elle effectue les étapes suivantes :
1. Récupère les derniers emails de Gmail.
2. Catégorise chaque email selon son contenu et son expéditeur.
3. Applique les étiquettes appropriées dans Gmail.

La réponse HTTP retournera un message indiquant le nombre d'emails traités.

## Technologies utilisées

- **Azure Functions** : Pour héberger la logique de traitement des emails.
- **Gmail API** : Pour interagir avec les emails.
- **OpenAI GPT-3.5** : Pour déterminer la catégorie des emails.
- **Azure Key Vault** : Pour sécuriser et stocker les secrets nécessaires.


