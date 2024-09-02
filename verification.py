import requests
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa, utils
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature
import hashlib


def extraire_cle_publique(cle_privee_path, cle_publique_path):
    """
    Extrait la clé publique à partir de la clé privée et l'enregistre dans un fichier PEM.
    """
    # Charger la clé privée
    with open(cle_privee_path, 'rb') as f:
        cle_privee = serialization.load_pem_private_key(
            f.read(),
            password=None,
            backend=default_backend()
        )

    # Extraire la clé publique
    cle_publique = cle_privee.public_key()

    # Sauvegarder la clé publique dans un fichier PEM
    with open(cle_publique_path, 'wb') as f:
        f.write(cle_publique.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))


def verifier_document(lien_pdf, signature, public_key):
    """
    Vérifie si un document signé a été modifié.
    """
    # 1. Calculer le hash du document actuel
    response = requests.get(lien_pdf)
    if response.status_code == 200:
        pdf_data = response.content
        hash_actuel = hashlib.sha256(pdf_data).digest()
    else:
        return f"Erreur lors du téléchargement du PDF: {response.status_code}"

    # 2. Vérifier la signature en utilisant la clé publique
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
    """
    Charge une clé publique à partir d'un fichier PEM.
    """
    with open(chemin_fichier, 'rb') as f:
        public_key = serialization.load_pem_public_key(
            f.read(),
            backend=default_backend()
        )
    return public_key


def charger_signature(chemin_fichier):
    """
    Charge la signature à partir d'un fichier.
    """
    with open(chemin_fichier, 'rb') as f:
        signature = f.read()
    return signature


# Étape 1 : Extraire la clé publique à partir de la clé privée
chemin_cle_privee = r"C:\Users\fayei\PycharmProjects\donneesMeta\cle_privee.pem"
chemin_cle_publique = r"C:\Users\fayei\PycharmProjects\donneesMeta\cle_publique.pem"
extraire_cle_publique(chemin_cle_privee, chemin_cle_publique)

# Étape 2 : Vérification du document avec la clé publique
lien_lecture = "https://drive.google.com/file/d/1Jf-z_FG4GmhPwh0CjYwwaG3Bq_7cF4BS/view?usp=sharing"
# "C:\Users\fayei\Downloads\Documents\FirndeBi_Teste.pdf"
signature = charger_signature(r"C:\Users\fayei\PycharmProjects\donneesMeta\signature.bin")
cle_publique = charger_cle_publique(chemin_cle_publique)

# Vérifier le document
resultat = verifier_document(lien_lecture, signature, cle_publique)
print(resultat)
# import hashlib
# from cryptography.hazmat.primitives import hashes
# from cryptography.hazmat.primitives.asymmetric import padding, rsa, utils
# from cryptography.hazmat.primitives import serialization
# from cryptography.hazmat.backends import default_backend
# from cryptography.exceptions import InvalidSignature
#
#
# def extraire_cle_publique(cle_privee_path, cle_publique_path):
#     """
#     Extrait la clé publique à partir de la clé privée et l'enregistre dans un fichier PEM.
#     """
#     # Charger la clé privée
#     with open(cle_privee_path, 'rb') as f:
#         cle_privee = serialization.load_pem_private_key(
#             f.read(),
#             password=None,
#             backend=default_backend()
#         )
#
#     # Extraire la clé publique
#     cle_publique = cle_privee.public_key()
#
#     # Sauvegarder la clé publique dans un fichier PEM
#     with open(cle_publique_path, 'wb') as f:
#         f.write(cle_publique.public_bytes(
#             encoding=serialization.Encoding.PEM,
#             format=serialization.PublicFormat.SubjectPublicKeyInfo
#         ))
#
#
# def verifier_document_local(chemin_pdf, signature, public_key):
#     """
#     Vérifie si un document PDF local signé a été modifié.
#     """
#     # 1. Calculer le hash du document local
#     with open(chemin_pdf, 'rb') as f:
#         pdf_data = f.read()
#         hash_actuel = hashlib.sha256(pdf_data).digest()
#
#     # 2. Vérifier la signature en utilisant la clé publique
#     try:
#         public_key.verify(
#             signature,
#             hash_actuel,
#             padding.PSS(
#                 mgf=padding.MGF1(hashes.SHA256()),
#                 salt_length=padding.PSS.MAX_LENGTH
#             ),
#             utils.Prehashed(hashes.SHA256())
#         )
#         return "Le document n'a pas été modifié."
#     except InvalidSignature:
#         return "Le document a été modifié ou la signature est invalide."
#
#
# def charger_cle_publique(chemin_fichier):
#     """
#     Charge une clé publique à partir d'un fichier PEM.
#     """
#     with open(chemin_fichier, 'rb') as f:
#         public_key = serialization.load_pem_public_key(
#             f.read(),
#             backend=default_backend()
#         )
#     return public_key
#
#
# def charger_signature(chemin_fichier):
#     """
#     Charge la signature à partir d'un fichier.
#     """
#     with open(chemin_fichier, 'rb') as f:
#         signature = f.read()
#     return signature
#
#
# # Étape 1 : Extraire la clé publique à partir de la clé privée
# chemin_cle_privee = r"C:\Users\fayei\PycharmProjects\donneesMeta\cle_privee.pem"
# chemin_cle_publique = r"C:\Users\fayei\PycharmProjects\donneesMeta\cle_publique.pem"
# extraire_cle_publique(chemin_cle_privee, chemin_cle_publique)
#
# # Étape 2 : Vérification du document avec la clé publique
# chemin_pdf_local = r"C:\Users\fayei\Downloads\Documents\FirndeBi_Teste.pdf"
# signature = charger_signature(r"C:\Users\fayei\PycharmProjects\donneesMeta\signature.bin")
# cle_publique = charger_cle_publique(chemin_cle_publique)
#
# # Vérifier le document local
# resultat = verifier_document_local(chemin_pdf_local, signature, cle_publique)
# print(resultat)
