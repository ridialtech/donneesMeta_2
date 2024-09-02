import requests
from PyPDF2 import PdfReader
from io import BytesIO
from datetime import datetime

def convertir_lien_google_drive(lien_lecture):

    try:
        debut_id = lien_lecture.find("/d/") + 3
        fin_id = lien_lecture.find("/view")
        file_id = lien_lecture[debut_id:fin_id]
        lien_telechargement = f"https://drive.google.com/uc?export=download&id={file_id}"
        return lien_telechargement
    except Exception as e:
        return f"Erreur lors de la conversion du lien : {e}"

def formater_date(date_str):

    try:
        # Suppression du préfixe "D:" si présent
        if date_str.startswith("D:"):
            date_str = date_str[2:]
        # Vérification et traitement du format avec décalage horaire
        if "+" in date_str or "-" in date_str:
            date_str = date_str.split("+")[0].split("-")[0]
        # Parsing de la date
        date_obj = datetime.strptime(date_str, "%Y%m%d%H%M%S")
        return date_obj.strftime("%d/%m/%Y %H:%M:%S")
    except Exception as e:
        return f"Format de date inconnu: {date_str}"

def extraire_metadonnees_pdf(lien):
    """
   on télécharge le PDF depuis le lien ensuite on  extrait les métadonnées.
    """
    if "drive.google.com" in lien:
        lien = convertir_lien_google_drive(lien)

    response = requests.get(lien)

    if response.status_code == 200:
        pdf_data = BytesIO(response.content)
        reader = PdfReader(pdf_data)
        metadata = reader.metadata

        metadata_traduit = {}
        traductions = {
            '/Title': 'Titre',
            '/Author': 'Auteur',
            '/Subject': 'Sujet',
            '/Creator': 'Créateur',
            '/Producer': 'Producteur',
            '/CreationDate': 'Date de création',
            '/ModDate': 'Date de modification',
            '/Keywords': 'Mots-clés'
        }

        for key, value in metadata.items():
            key_fr = traductions.get(key, key)  # clé d'origine si pas de traduction
            if "Date" in key_fr and isinstance(value, str):
                value = formater_date(value)  # Formater les dates
            metadata_traduit[key_fr] = value

        return metadata_traduit
    else:
        return f"Erreur lors du téléchargement du PDF: {response.status_code}"

# Exemple
lien_lecture = "https://drive.google.com/file/d/1IYBa75tVkfOWr428V5p9VZAxmigpGUWZ/view?usp=sharing"
# lien_lecture = "https://drive.google.com/file/d/1QMDqmwzaCX31XSU8qArdW_nJtDHnJ_aj/view?usp=drive_link"
# lien_lecture = "https://drive.google.com/file/d/1lHwj5FFSGjXtiB_QMNtlgcv-i27xrTp0/view?usp=drive_link"
metadonnees = extraire_metadonnees_pdf(lien_lecture)

if isinstance(metadonnees, dict):
    for key, value in metadonnees.items():
        print(f"{key}: {value}")
else:
    print(metadonnees)

# lien json pour le test
# {
#     "lien_pdf": "https://drive.google.com/file/d/1hRoZjtMA_GxhXLcmPD7p11xOFN0-Smi5/view?usp=drive_link"
# }
