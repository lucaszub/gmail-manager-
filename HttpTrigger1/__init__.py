import logging
import openai
import azure.functions as func
from azure.identity import DefaultAzureCredential
from azure.keyvault.secrets import SecretClient
import json
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from google.auth.transport.requests import Request
import base64
import re

# Initialisation de l'accès au Key Vault
key_vault_url = "https://openai-api-key.vault.azure.net/"
credential = DefaultAzureCredential()  # Utilise Managed Identity si déployé sur Azure
secret_client = SecretClient(vault_url=key_vault_url, credential=credential)

# Récupération de la clé API depuis le Key Vault
def get_openai_api_key():
    try:
        logging.info("Tentative de récupération de la clé API depuis Key Vault...")
        secret_name = "OPENAI-API-KEY"
        logging.info(f"Nom du secret recherché : {secret_name}")
        secret = secret_client.get_secret(secret_name)
        logging.info(f"Clé API récupérée avec succès depuis Key Vault (nom du secret : {secret_name}).")
        return secret.value
    except Exception as e:
        logging.error(f"Erreur lors de la récupération de la clé API depuis Key Vault : {e}")
        raise

# Fonction pour interroger l'API OpenAI avec la nouvelle API
def get_openai_response(prompt):
    try:
        logging.info("Début de l'interrogation de l'API OpenAI...")
        api_key = get_openai_api_key()
        openai.api_key = api_key

        # Utilisation de la méthode ChatCompletion pour interroger GPT
        logging.info("Appel à l'API OpenAI pour déterminer la catégorie avec le prompt : %s", prompt)
        response = openai.ChatCompletion.create(
            model="gpt-3.5-turbo",
            messages=[{"role": "user", "content": prompt}],
            temperature=0.3
        )
        logging.info("Réponse de l'API OpenAI reçue avec succès.")
        return response['choices'][0]['message']['content'].strip()
    except Exception as e:
        logging.error(f"Erreur lors de l'appel à l'API OpenAI : {e}")
        raise

# Fonction pour récupérer les emails depuis Gmail
# Fonction pour récupérer les emails depuis Gmail
def get_gmail_emails():
    try:
        logging.info("Tentative de récupération des emails...")

        # Récupérer les secrets depuis Azure Key Vault
        credentials_secret = secret_client.get_secret("GMAIL-CREDENTIALS")
        token_secret = secret_client.get_secret("token")
        credentials = json.loads(credentials_secret.value)
        token = json.loads(token_secret.value)

        # Créer les credentials à partir du refresh_token
        creds = Credentials(
            token=token["token"],
            refresh_token=token["refresh_token"],
            client_id=token["client_id"],
            client_secret=token["client_secret"],
            token_uri=token["token_uri"]
        )

        # Actualiser les credentials si nécessaire
        if creds.expired and creds.refresh_token:
            creds.refresh(Request())

        # Créer un service Gmail
        service = build('gmail', 'v1', credentials=creds)

        # Récupérer les 20 derniers emails
        results = service.users().messages().list(userId='me', labelIds=['INBOX']).execute()
        messages = results.get('messages', [])

        if not messages:
            logging.info("Aucun message trouvé.")
            return []

        email_data = []
        for message in messages[:20]:  # Limiter à 20 messages
            msg = service.users().messages().get(userId='me', id=message['id']).execute()
            payload = msg['payload']
            headers = payload['headers']
            sender = ""
            subject = ""
            for header in headers:
                if header['name'] == 'From':
                    sender = header['value']
                if header['name'] == 'Subject':
                    subject = header['value']

            # Récupérer le contenu du message (texte brut ou HTML)
            body = ""
            if 'parts' in payload:
                for part in payload['parts']:
                    if part['mimeType'] == 'text/plain':
                        body = part['body']['data']

            # Ajouter l'email avec l'ID et le contenu nettoyé
            cleaned_body = clean_email_body(body)
            email_data.append({
                "id": message['id'],  # Ajouter l'ID de l'email
                "sender": sender,
                "subject": subject,
                "cleaned_body": cleaned_body
            })

        logging.info(f"{len(email_data)} emails récupérés.")
        return email_data

    except HttpError as error:
        logging.error(f"Erreur lors de la récupération des messages: {error}")
        return []


# Fonction pour nettoyer le corps de l'email en supprimant les mots fréquents et les liens
def clean_email_body(body):
    try:
        # Décoder le contenu base64 et effectuer un nettoyage
        decoded_body = base64.urlsafe_b64decode(body).decode('utf-8')  # Décoder le corps
        # Supprimer les liens
        decoded_body = re.sub(r'http[s]?://\S+', '', decoded_body)

        stop_words = set([  # Liste de stop words
            "a", "an", "le","la", "the", "and", "but", "or", "for", "nor", "so", "on", "at", "by", "with", "about", "as", "of", "to", "from", "in", "out", "up", "down", "over", "under", "again", "further", "then", "once", "here", "there", "when", "where", "why", "how"
        ])  
        word_tokens = decoded_body.split()  # Tokenisation par espace

        # Filtrer les stop words
        filtered_words = [word for word in word_tokens if word.lower() not in stop_words]
        return ' '.join(filtered_words[:1500])  # Limiter à 1500 tokens sans stop words
    except Exception as e:
        logging.error(f"Erreur lors du nettoyage du corps de l'email : {e}")
        return ""

# Fonction pour déterminer la catégorie en fonction des mots-clés avec un prompt pour OpenAI
def categorize_email(sender, subject, body):
    try:
        # Préparer le prompt pour l'API OpenAI
        prompt = f"""
            Nous voulons catégoriser cet email en fonction de son expéditeur, de son sujet et de son corps.
            Les catégories possibles sont : 'Urgent', 'Finance', 'Rendez-vous', 'Newsletter', 'Social', 'Non catégorisé'.

            Règles :
            - Si l'email provient des personnes suivantes : "Aziliz Lemonnier", "Nicolas Liziard", ou "Zubiarrain" ou mentionne "France Travail", catégorisez-le comme 'Urgent'.
            - Si l'email parle de questions financières, comme des paiements, des factures, des transactions bancaires ou des rapports financiers, catégorisez-le comme 'Finance'.
            - Si l'email concerne un rendez-vous, des dates, une rencontre ou une planification, catégorisez-le comme 'Rendez-vous'.
            - Si l'email contient des informations sur une newsletter, des abonnements ou des actualités, catégorisez-le comme 'Newsletter'.
            - Si l'email concerne des réseaux sociaux, des messages sociaux, des invitations ou des événements, catégorisez-le comme 'Social'.
            - Pour tout autre type d'email, catégorisez-le comme 'Non catégorisé'.
            

            Expéditeur: {sender}
            Sujet: {subject}
            Corps: {body}

            Catégorie :
            """


        # Appeler l'API OpenAI pour déterminer la catégorie
        category = get_openai_response(prompt)
        return category

    except Exception as e:
        logging.error(f"Erreur lors de la catégorisation avec OpenAI : {e}")
        return "Non catégorisé"

# Fonction pour créer des étiquettes Gmail si elles n'existent pas
def create_label(service, label_name):
    try:
        # Vérifier si l'étiquette existe déjà
        results = service.users().labels().list(userId='me').execute()
        labels = results.get('labels', [])
        existing_labels = [label['name'] for label in labels]

        if label_name not in existing_labels:
            label_object = {
                "name": label_name,
                "labelListVisibility": "labelShow",
                "messageListVisibility": "show"
            }
            service.users().labels().create(userId='me', body=label_object).execute()
            logging.info(f"Étiquette '{label_name}' créée.")
        else:
            logging.info(f"Étiquette '{label_name}' existe déjà.")
    except HttpError as error:
        logging.error(f"Erreur lors de la création de l'étiquette '{label_name}': {error}")

# Fonction pour appliquer une étiquette à un email
# Fonction pour appliquer une étiquette à un email
def apply_label_to_email(service, email_id, label_id):
    try:
        message = service.users().messages().modify(
            userId='me',
            id=email_id,
            body={'addLabelIds': [label_id]}
        ).execute()
        logging.info(f"Étiquette appliquée à l'email {email_id}.")
    except HttpError as error:
        logging.error(f"Erreur lors de l'application de l'étiquette à l'email {email_id}: {error}")

# Fonction principale de l'Azure Function

def main(req: func.HttpRequest) -> func.HttpResponse:
    logging.info('Azure Function HTTP trigger a démarré.')

    try:
        # Récupérer les emails depuis Gmail
        email_data = get_gmail_emails()
        if not email_data:
            return func.HttpResponse("Aucun email trouvé.", status_code=200)

        # Créer un service Gmail
        credentials_secret = secret_client.get_secret("GMAIL-CREDENTIALS")
        token_secret = secret_client.get_secret("token")
        credentials = json.loads(credentials_secret.value)
        token = json.loads(token_secret.value)

        creds = Credentials(
            token=token["token"],
            refresh_token=token["refresh_token"],
            client_id=token["client_id"],
            client_secret=token["client_secret"],
            token_uri=token["token_uri"]
        )

        if creds.expired and creds.refresh_token:
            creds.refresh(Request())

        service = build('gmail', 'v1', credentials=creds)

        # Liste des catégories possibles
        categories = ['Urgent', 'Finance', 'Rendez-vous', 'Newsletter', 'Social', 'Non catégorisé']

        # Créer les étiquettes si elles n'existent pas déjà
        for category in categories:
            create_label(service, category)

        # Récupérer la liste des étiquettes existantes après leur création
        existing_labels = service.users().labels().list(userId='me').execute().get('labels', [])

        # Appliquer les étiquettes aux emails récupérés
        for email in email_data:
            sender = email["sender"]
            subject = email["subject"]
            cleaned_body = email["cleaned_body"]

            # Déterminer la catégorie de l'email
            category = categorize_email(sender, subject, cleaned_body)

            # Trouver l'ID de l'étiquette correspondant à la catégorie
            label_id = None
            for label in existing_labels:
                if label['name'] == category:
                    label_id = label['id']
                    break  # Sortir dès que l'étiquette est trouvée

            if label_id:
                # Appliquer l'étiquette à l'email
                apply_label_to_email(service, email["id"], label_id)
            else:
                logging.error(f"Aucune étiquette trouvée pour l'email {email['id']}")

        return func.HttpResponse(f"{len(email_data)} emails traités avec succès.", status_code=200)

    except Exception as e:
        logging.error(f"Erreur dans la fonction principale : {e}")
        return func.HttpResponse("Une erreur est survenue.", status_code=500)
