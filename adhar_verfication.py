aadhar_file = "/home/dj/djay/offlineaadhaar20240309044306261.xml"
cert_path = "/home/dj/djay/uidai_offline_publickey_17022026.cer"
from lxml import etree

import xmlsec

#manager = xmlsec.KeysManager()
template = etree.parse(aadhar_file).getroot()
xmlsec.tree.add_ids(template, ["ID"])
signature_node = xmlsec.tree.find_node(template, xmlsec.constants.NodeSignature)
# Create a digital signature context (no key manager is needed).
import pdb; pdb.set_trace()
ctx = xmlsec.SignatureContext()
key = xmlsec.Key.from_file(cert_path, xmlsec.constants.KeyDataFormatCertPem, None)
#manager.add_key(key)

# Set the key on the context.
ctx.key = key
ctx.verify(signature_node)
