import PyKCS11
import binascii
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15
from cryptography.hazmat.primitives.hashes import SHA1, Hash




lib = '/usr/lib/x86_64-linux-gnu/pkcs11/opensc-pkcs11.so'
pkcs11 = PyKCS11.PyKCS11Lib()
pkcs11.load(lib)
slots = pkcs11.getSlotList(tokenPresent=True)

all_attributes = list(PyKCS11.CKA.keys())
#Filter attributes
all_attributes = [e for e in all_attributes if isinstance(e, int)]

for slot in range(1):

    session = pkcs11.openSession(slot)
    session.login('1111') # DANGER!!! USE YOUR PINCODE!!
    for obj in session.findObjects():
        attr = session.getAttributeValue(obj, all_attributes)

        attrDict = dict(list(zip(all_attributes, attr)))
        # print("Type:", PyKCS11.CKO[attrDict[PyKCS11.CKA_CLASS]], "\tLabel:", attrDict[PyKCS11.CKA_LABEL], "\tID:",attrDict[PyKCS11.CKA_ID])

        if attrDict[PyKCS11.CKA_CLASS] == PyKCS11.CKO_PRIVATE_KEY:
            if attrDict[PyKCS11.CKA_ID][0] == 69:     # signature
                private_key = obj

        if attrDict[PyKCS11.CKA_CLASS] == PyKCS11.CKO_CERTIFICATE:
            if attrDict[PyKCS11.CKA_ID][0] == 69:
                cert_obj = obj
                cert_der_data = bytes(cert_obj.to_dict()['CKA_VALUE'])

    session.logout()

cert = x509.load_der_x509_certificate(cert_der_data, default_backend)
cert = cert.public_bytes(encoding=serialization.Encoding.PEM)


f = open('callerList.pem',"ab")
f.write(cert)
f.close

