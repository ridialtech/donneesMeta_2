from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import utils
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature
import hashlib

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

def charger_cle_privee(chemin_fichier):
    """
    Charge une clé privée à partir d'un fichier PEM.
    """
    with open(chemin_fichier, 'rb') as f:
        private_key = serialization.load_pem_private_key(
            f.read(),
            password=None,
            backend=default_backend()
        )
    return private_key

def charger_cle_publique(private_key):
    """
    Extrait la clé publique à partir de la clé privée.
    """
    public_key = private_key.public_key()
    return public_key

def charger_signature(chemin_fichier):
    """
    Charge une signature depuis un fichier.
    """
    with open(chemin_fichier, 'rb') as f:
        signature = f.read()
    return signature

def verifier_signature(hachage, signature, public_key):
    """
    Vérifie si la signature est valide pour le hachage donné.
    """
    try:
        public_key.verify(
            signature,
            bytes.fromhex(hachage),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            utils.Prehashed(hashes.SHA256())
        )
        return True
    except InvalidSignature:
        return False

# Exemple d'utilisation
chemin_fichier_pdf = r"C:\Users\fayei\Documents\teste1.pdf"
chemin_cle_privee = 'cle_privee.pem'
chemin_signature = 'signature.bin'

# 1. Hash du document PDF
hachage_pdf = hasher_pdf(chemin_fichier_pdf)
print(f"Hachage du PDF: {hachage_pdf}")

# 2. Charger la clé privée et en extraire la clé publique
cle_privee = charger_cle_privee(chemin_cle_privee)
cle_publique = charger_cle_publique(cle_privee)

# 3. Charger la signature
signature = charger_signature(chemin_signature)

# 4. Vérification de la signature
signature_valide = verifier_signature(hachage_pdf, signature, cle_publique)

if signature_valide:
    print("La signature est valide.")
else:
    print("La signature n'est pas valide.")
