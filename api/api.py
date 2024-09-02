from flask import Flask, request, jsonify
import requests
from PyPDF2 import PdfReader
from io import BytesIO
from datetime import datetime

app = Flask(__name__)

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
        if date_str.startswith("D:"):
            date_str = date_str[2:]
        if "+" in date_str or "-" in date_str:
            date_str = date_str.split("+")[0].split("-")[0]
        date_obj = datetime.strptime(date_str, "%Y%m%d%H%M%S")
        return date_obj.strftime("%d/%m/%Y %H:%M:%S")
    except Exception as e:
        return f"Format de date inconnu: {date_str}"

def extraire_metadonnees_pdf(lien):
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
            key_fr = traductions.get(key, key)
            if "Date" in key_fr and isinstance(value, str):
                value = formater_date(value)
            metadata_traduit[key_fr] = value

        return metadata_traduit
    else:
        return f"Erreur lors du téléchargement du PDF: {response.status_code}"

@app.route('/api/extraction_metadonnees', methods=['POST'])
def extraction_metadonnees():
    data = request.json
    lien_lecture = data.get('lien_lecture', '')
    metadonnees = extraire_metadonnees_pdf(lien_lecture)
    return jsonify(metadonnees)

if __name__ == '__main__':
    app.run(debug=True)
