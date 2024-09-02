from flask import Flask, request, jsonify
import hashlib
import requests
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import utils
from cryptography.hazmat.backends import default_backend

app = Flask(__name__)


def hasher_pdf(lien_pdf):
    """
    Télécharge le PDF et calcule son hash SHA-256.
    """
    response = requests.get(lien_pdf)
    if response.status_code == 200:
        pdf_data = response.content
        sha256_hash = hashlib.sha256(pdf_data).hexdigest()
        return sha256_hash
    else:
        return None


def generer_cle_privee():
    """
    Génère une clé privée RSA pour la signature.
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    return private_key


def signer_hachage(hachage, private_key):
    """
    Signe le hachage avec la clé privée.
    """
    signature = private_key.sign(
        bytes.fromhex(hachage),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        utils.Prehashed(hashes.SHA256())
    )
    return signature


def sauvegarder_cle_privee(private_key, chemin_fichier):
    """
    Sauvegarde la clé privée dans un fichier PEM.
    """
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    with open(chemin_fichier, 'wb') as f:
        f.write(pem)


def sauvegarder_signature(signature, chemin_fichier):
    """
    Sauvegarde la signature dans un fichier.
    """
    with open(chemin_fichier, 'wb') as f:
        f.write(signature)


@app.route('/api/signature', methods=['POST'])
def signature_pdf():
    data = request.json
    lien_lecture = data.get('lien_pdf')

    # 1. Hash du document PDF
    hachage_pdf = hasher_pdf(lien_lecture)
    if hachage_pdf is None:
        return jsonify({"error": "Erreur lors du téléchargement du PDF"}), 400

    # 2. Génération de la clé privée
    cle_privee = generer_cle_privee()

    # 3. Signature du hachage
    signature = signer_hachage(hachage_pdf, cle_privee)

    # 4. Sauvegarder la clé privée
    sauvegarder_cle_privee(cle_privee, 'cle_privee.pem')

    # 5. Sauvegarder la signature
    sauvegarder_signature(signature, 'signature.bin')

    return jsonify({
        "message": "Clé privée et signature enregistrées.",
        "hachage_pdf": hachage_pdf,
        "signature": signature.hex()
    })


if __name__ == '__main__':
    app.run(debug=True)

# lien json pour le test
# {
#     {
#     "lien_pdf": "https://drive.google.com/file/d/1hRoZjtMA_GxhXLcmPD7p11xOFN0-Smi5/view?usp=drive_link"
# }

# }
