from flask import Flask, request, jsonify
import requests
import hashlib
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, utils
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature

app = Flask(__name__)


def extraire_cle_publique(cle_privee_path, cle_publique_path):
    """
    Extrait la clé publique à partir de la clé privée et l'enregistre dans un fichier PEM.
    """
    with open(cle_privee_path, 'rb') as f:
        cle_privee = serialization.load_pem_private_key(
            f.read(),
            password=None,
            backend=default_backend()
        )
    cle_publique = cle_privee.public_key()
    with open(cle_publique_path, 'wb') as f:
        f.write(cle_publique.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))


def verifier_document(lien_pdf, signature, public_key):
    """
    Vérifie si un document signé a été modifié.
    """
    response = requests.get(lien_pdf)
    if response.status_code == 200:
        pdf_data = response.content
        hash_actuel = hashlib.sha256(pdf_data).digest()
    else:
        return f"Erreur lors du téléchargement du PDF: {response.status_code}"

    try:
        public_key.verify(
            signature,
            hash_actuel,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            utils.Prehashed(hashes.SHA256())
        )
        return "Le document n'a pas été modifié."
    except InvalidSignature:
        return "Le document a été modifié ou la signature est invalide."


def charger_cle_publique(chemin_fichier):
    with open(chemin_fichier, 'rb') as f:
        public_key = serialization.load_pem_public_key(
            f.read(),
            backend=default_backend()
        )
    return public_key


def charger_signature(chemin_fichier):
    with open(chemin_fichier, 'rb') as f:
        signature = f.read()
    return signature


@app.route('/api/verifier', methods=['POST'])
def verifier_pdf():
    data = request.json
    lien_pdf = data.get('lien_pdf')
    chemin_signature = data.get('chemin_signature')
    chemin_cle_publique = data.get('chemin_cle_publique')

    if not lien_pdf or not chemin_signature or not chemin_cle_publique:
        return jsonify({"error": "Les chemins du PDF, de la signature, et de la clé publique sont requis."}), 400

    cle_publique = charger_cle_publique(chemin_cle_publique)
    signature = charger_signature(chemin_signature)

    resultat = verifier_document(lien_pdf, signature, cle_publique)

    return jsonify({"resultat": resultat})


if __name__ == '__main__':
    app.run(debug=True)


# lien json pour test avec postman
# {
#     "lien_pdf": "https://drive.google.com/file/d/10R5jx6xpcGxb66To84_Yl_IQ-esNIOQ2/view?usp=sharing",
#     "chemin_signature": "C:\\Users\\fayei\\PycharmProjects\\donneesMeta\\apiScriptLocal\\signature.bin",
#     "chemin_cle_publique": "C:\\Users\\fayei\\PycharmProjects\\donneesMeta\\cle_publique.pem"
# }
