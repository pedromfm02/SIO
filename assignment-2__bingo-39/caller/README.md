# CALLER
Files:
 - caller.py: ficheiro com todo o processo do caller
 - sign.py: ficheiro com a função cc_sign que assina o certificado do cc.

The caller needs to have a specific card that needs to be verified by the certificates that are in a list on the playing area.
```python
    message = {'header': 'CALLER', 'method': '', 'body': {'public_key': public_key_to_send, 'username': 'manel'}}

        signed_message,cc_cert = cc_sign(bytes(str(message),'utf-8'))

        cc_cert_data = cc_cert.public_bytes(encoding=serialization.Encoding.PEM)

        message = {'header':'CALLER','signed message':signed_message, 'plaintext':message, 'cc_cert':cc_cert_data}
        
        send_msg( s, pickle.dumps( message ) )

        received = pickle.loads(recv_msg(s))

        if 'method' in received:
            if received['method']== "Can't authenticate":
                return 0
```