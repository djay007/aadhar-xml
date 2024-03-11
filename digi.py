import xml.etree.ElementTree as ET
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import utils
from cryptography.hazmat.primitives.serialization import load_pem_public_key

# Get file paths (replace with your actual paths)

XMLFilePath = "/home/dj/djay/offlineaadhaar20240309044306261.xml"
KeyFilePath = "/home/dj/djay/uidai_offline.pem"
# Load XML content
tree = ET.parse(XMLFilePath)
root = tree.getroot()
# Extract signature value
import xml.etree.ElementTree as ET
from base64 import b64decode

# Find the Signature element
signature_elem = root.find('.//{http://www.w3.org/2000/09/xmldsig#}Signature')

# Find the SignatureValue element within Signature
signature_value_elem = signature_elem.find('.//{http://www.w3.org/2000/09/xmldsig#}SignatureValue')

# Get the text content of SignatureValue (which is the signature value)
signature_value = signature_value_elem.text.strip()

# if signature_elem is not None:
#     signature_elem.getparent().remove(signature_elem)
# Read and parse public key
with open(KeyFilePath, "rb") as key_file:
    public_key_bytes = key_file.read()

public_key = x509.load_pem_x509_certificate(public_key_bytes).public_key()
# Load public key object
# public_key = load_pem_public_key(public_key_bytes)
# Verify signature
signer = padding.PKCS1v15()
expected_sig = b64decode(signature_value)
msg_bytes = ET.tostring(root, encoding="utf-8")

try:
    # public_key.verify(expected_sig, msg_bytes, padding.PKCS1v15(), hashes.SHA256())
    signer.verify(public_key, expected_sig, msg_bytes, hashes.SHA256())
    print("XML Validate Successfully")
except Exception as e:
    print("XML Validation Failed", e)
