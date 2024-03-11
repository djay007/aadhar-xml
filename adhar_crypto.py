from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.x509 import load_pem_x509_certificate
from base64 import b64decode
import xml.etree.cElementTree as etree

def verify_xml_signature(xml_path, public_key_path, hash_algorithm=hashes.SHA256()):
    try:
        with open(xml_path, "r") as xml_file:
            xml_content = xml_file.read()
        
        with open(public_key_path, "rb") as cert_file:
            cert = load_pem_x509_certificate(cert_file.read())
    except IOError as e:
        print("Error reading files:", e)
        return False
    
    xml_tree = etree.XML(xml_content)
    # Find the Signature element
    signature_element = xml_tree.find(".//{http://www.w3.org/2000/09/xmldsig#}Signature")
    # Remove the Signature element if found
    if signature_element is not None:
        xml_tree.remove(signature_element)
    else:
        print("Signature element not found in XML.")
        return False

    # Convert the modified XML tree back to a string
    modified_xml_string = etree.tostring(xml_tree).decode()

    try:
        signature = etree.tostring(signature_element).decode()
        public_key = cert.public_key()
        public_key.verify(
            b64decode(signature),
            xml_content.encode("utf-8"),
            padding.PSS(
                mgf=padding.MGF1(algorithm=hash_algorithm),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hash_algorithm
        )
        return True
    except ValueError:
        print("Verification failed: Invalid signature.")
        return False
    except Exception as e:
        print("Verification failed due to an unexpected error:", e)
        return False

xml_path = "C://Users//Dhananjay//OneDrive//Desktop//adhar//offlineaadhaar20240309044306261.xml"
public_key_path = "C://Users//Dhananjay//OneDrive//Desktop//adhar//uidai_offline_publickey_17022026.cer"

if verify_xml_signature(xml_path, public_key_path):
    print('Digital Signature validated')
else:
    print('Digital Signature not validated')
