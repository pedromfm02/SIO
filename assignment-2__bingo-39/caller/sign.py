import PyKCS11
import binascii
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend as db
from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15
from cryptography.hazmat.primitives.hashes import SHA1, Hash


def cc_sign(text):
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
            if attrDict[PyKCS11.CKA_CLASS] == PyKCS11.CKO_CERTIFICATE:
                if attrDict[PyKCS11.CKA_ID][0] == 69:
                    cert_obj = obj
                    cert_der_data = bytes(cert_obj.to_dict()['CKA_VALUE'])
            

        session.logout()


    #extract public key

    cert = x509.load_der_x509_certificate(cert_der_data, backend=db())

    #digital signature


    mechanism = PyKCS11.Mechanism(PyKCS11.CKM_SHA1_RSA_PKCS, None)

    signature = bytes(session.sign(private_key, text, mechanism))


    
    # md = Hash(SHA1(), backend=db())
    # md.update(text)
    # digest = md.finalize()


    # if(card_key_recv != None):
    #     print(card_key_recv)
    #     public_key = card_key_recv



    # public_key.verify(
    #     signature,
    #     digest,
    #     PKCS1v15(),
    #     SHA1()
    # )

    return (signature, cert)