
# PLAYING AREA
Files:
 - parea.py: file with all the playing area process
 - getCallerCert.py: file that gets the caller's certificate

When adding cards to caller, run getCaller.py with the card inserted.

Players have a card with the signed message and the certificate
```python
    message = {'header': 'PLAYER', 'body':  {'public_key': public_key_to_send, 'username': 'ze'}}

        signed_message,cc_cert = cc_sign(bytes(str(message),'utf-8'))

        cc_cert_data = cc_cert.public_bytes(encoding=serialization.Encoding.PEM)

        message = {'header':'player','signed message':signed_message, 'plaintext':message, 'cc_cert':cc_cert_data}


        send_msg(s, pickle.dumps( message ))
```