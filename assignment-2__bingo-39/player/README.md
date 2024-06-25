
# PLAYER

How to start player.py:
```python
    python3 player.py [port] [name] [cheat]
```
 - [name] - players' username
 - [cheat] - if the player wants to cheat, he has to write "cheat". Otherwise, the player should write something else


Files:
 - player.py: ficheiro com todo o processo do player
 - sign.py: ficheiro com a função cc_sign que assina o certificado do cc.



Players têm cartao com mensagem assinada e certificado
```python
    message = {'header': 'PLAYER', 'body':  {'public_key': public_key_to_send, 'username': 'ze'}}

        signed_message,cc_cert = cc_sign(bytes(str(message),'utf-8'))

        cc_cert_data = cc_cert.public_bytes(encoding=serialization.Encoding.PEM)

        message = {'header':'player','signed message':signed_message, 'plaintext':message, 'cc_cert':cc_cert_data}


        send_msg(s, pickle.dumps( message ))
```