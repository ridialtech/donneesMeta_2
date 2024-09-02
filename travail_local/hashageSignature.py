import hashlib
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import utils
from cryptography.hazmat.backends import default_backend

def hasher_pdf(chemin_fichier):
    """
    Lit le PDF depuis un chemin local et calcule son hash SHA-256.
    """
    try:
        with open(chemin_fichier, 'rb') as f:
            pdf_data = f.read()
            sha256_hash = hashlib.sha256(pdf_data).hexdigest()
            return sha256_hash
    except FileNotFoundError:
        return "Erreur: Le fichier n'a pas été trouvé."

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

# Exemple
# chemin_fichier_pdf = r"C:\Users\fayei\Downloads\Documents\FirndeBi_Teste.pdf"
# "C:\Users\fayei\Documents\teste1.pdf"
chemin_fichier_pdf = r"C:\Users\fayei\Documents\teste1.pdf"

# 1. Hash du document PDF
hachage_pdf = hasher_pdf(chemin_fichier_pdf)
print(f"Hachage du PDF: {hachage_pdf}")

# 2. Génération de la clé privée
cle_privee = generer_cle_privee()

# 3. Signature du hachage
signature = signer_hachage(hachage_pdf, cle_privee)

# 4. Sauvegarder la clé privée
sauvegarder_cle_privee(cle_privee, 'cle_privee.pem')

# 5. Sauvegarder la signature
sauvegarder_signature(signature, 'signature.bin')

print("Clé privée et signature enregistrées.")
