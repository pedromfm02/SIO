#!/bin/python

import sys
import socket
import selectors
import pickle
import random
import logging
import binascii
import csv
import time
import datetime
import hashlib
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import dsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography import x509




import os
current = os.path.dirname(os.path.realpath('messages.py'))
parent = os.path.dirname(current)
sys.path.append(parent) 
from messages import send_msg, recv_msg, exact_recv
#from card import verify


finished = False
LOG_FILE = 'playingarea.log'
USER_LIST_FILE = 'user_list.csv'

logging.basicConfig(
    handlers=[
    logging.FileHandler(LOG_FILE),
    logging.StreamHandler()], 
    format='%(sequence)s , %(asctime)s , %(hash)s , %(message)s, %(signature)s', 
    level=logging.DEBUG
)

private_key = dsa.generate_private_key(
    key_size=1024,
)

public_key = private_key.public_key()

public_key_to_send = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

public_key_to_send.splitlines()[0]

prev_entry = ""


def get_audit_log():
    with open(LOG_FILE) as f:
        log_file = f.read()
        ##print(f)
        f.close()
    
    return log_file

def get_user_list():

    return 

user_info = {}


def dispatch( srv_socket ):
    selector = selectors.DefaultSelector()

    srv_socket.setblocking( False )
    selector.register( srv_socket, selectors.EVENT_READ, data=None )

    player_id = 1
    game = False
    users = {}
    users_keys = {}
    users_pub_keys = {}

    while True:
        events = selector.select( timeout=None )
        for key, mask in events:

            # Check for a new client connection
            if key.fileobj == srv_socket:

                if not game:

                    clt_socket, clt_addr = srv_socket.accept()
                    clt_socket.setblocking( True )

                    # Add it to the sockets under scrutiny
                    selector.register( clt_socket, selectors.EVENT_READ, data=None )
                    data = recv_msg( clt_socket )
                    data = pickle.loads(data)

                    if data['header'] == 'CALLER':
                    

                        if not users:
                            
                            cc_verify(data['signed message'],data['plaintext'], data['cc_cert'])
                            f = open('callerList.pem',"rb")

                            certs = []
                            cert_as_str = b''

                            for line in f.readlines():
                                cert_as_str += line
                                if line == b'-----END CERTIFICATE-----\n':
                                    certs.append(cert_as_str)
                                    cert_as_str = b''

                            f.close
                            caller_auth = False
                            for cert in certs:
                                if cert == data['cc_cert']:
                                    caller_auth = True
                            
                            if caller_auth==False:
                                print("caller is not right")
                                message = {'header':'PAREA', 'method':"Can't authenticate"}
                                send_msg(clt_socket,pickle.dumps(message))
                                prev_entry = do_log(clt_socket, users, "", "Caller rejected", data['signed message'])
                                break
                            

                            users[0] = clt_socket 
                            prev_entry = do_log(clt_socket, users, "", "Caller added", data['signed message'])

                            user_pub_key = data['plaintext']['body']['public_key']
                            username = data['plaintext']['body']['username']

                            

                            #print('caller public key received')
                            #plaintext = "first message of playing area"
                            message = {'header':'PAREA', 'public_key': public_key_to_send}

                            #signed_message = private_key.sign(pickle.dumps(message), hashes.SHA256())

                            #message = {'signed_message': signed_message, 'plaintext': pickle.dumps(message)}

                            send_msg(clt_socket, pickle.dumps( message ))
                            prev_entry = do_log(clt_socket, users, prev_entry, "Caller rejected", data['signed message'])



                            user_info[0] = (username, user_pub_key)


                    else:
                        #recebe mensagem do user guarda o username e a pub_key e envia para caller
                        try:
                            cc_verify(data['signed message'],data['plaintext'], data['cc_cert'])
                        except:
                            #print("invalid")
                            #print(data['signed message'])
                            #print(data['plaintext'])
                            #print(data['cc_key'])
                            pass
                        prev_entry = do_log(clt_socket, users, prev_entry, "Player added", data['signed message'])
                        data = data['plaintext']
                        
                        username = data['body']['username']
                        users[player_id] = clt_socket

                        

                        user_pub_key = data['body']['public_key']

                        username = data['body']['username']
                        #print('player public key and username received')


                        message = {'header':'PAREA', 'public_key': public_key_to_send}

                        send_msg(clt_socket, pickle.dumps( message ))
                        prev_entry = do_log(clt_socket, users, prev_entry, message, "")


                        message = {'header': 'PAREA', 'body': {'username': username, 'player_id':player_id, 'pub_key': user_pub_key}}
                        signed_message = private_key.sign(pickle.dumps(message), hashes.SHA256())

                        message = {'signed_message': signed_message, 'plaintext': pickle.dumps(message)}
                        
                        send_msg(users[0], pickle.dumps( message ))
                        prev_entry = do_log(clt_socket, users, prev_entry, message, signed_message)


                        user_info[player_id] = (username, user_pub_key)      

                        player_id += 1



                else:
                    print('playing area closed')

                    # Add it to the sockets under scrutiny
                    #caller_sck = users[0]

                    #message = {'header': '', 'body': 'game started'}
                    #data = pickle.loads(recv_msg(caller_sck))
                    #signed_message = private_key.sign(pickle.dumps(message), hashes.SHA256())
#
                    #message = {'signed_message': signed_message, 'plaintext': pickle.dumps(message)}
                    #send_msg(caller_sck, message)

            # Client data is available for reading

            else:
                data = recv_msg( key.fileobj )


                if data == None: # Socket closed
                    selector.unregister( key.fileobj )
                    key.fileobj.close()
                    prev_entry = do_log(clt_socket, users, prev_entry, "socket closed", "")
                    
                    continue
                
                data = pickle.loads( data )
                print(data)
                sign_message = data['signed_message']
                data = pickle.loads(data['plaintext'])
                #print(data)
                header = data['header']
                method = data['method']
                body = data['body']

                if header == 'CALLER':
                    if method == 'close playing area':
                        prev_entry = do_log(clt_socket, users, prev_entry, "Playing area closed", sign_message)

                        #print('close playing area')
                        game = True
                        for user in users:
                            if user == 0:
                                continue
                            else:
                                message = {'header': 'PLAYING AREA', 'method':'user_info', 'body': user_info}

                                signed_message = private_key.sign(pickle.dumps(message), hashes.SHA256())

                                message = {'signed_message': signed_message, 'plaintext': pickle.dumps(message)}

                                send_msg(users[user], pickle.dumps(message))
                                prev_entry = do_log(users[user],users, prev_entry, message, signed_message)

                        
                        caller_sck = users[0]
                        cards = {}
                        solutions = {}
                        consensus = {}
                        message = {'header': '', 'body': 'game started'}
                        #pedi aos players os cards
                        for user in users:
                            if user == 0:
                                continue
                            message = {'header': '', 'body': 'game started'}
                            signed_message = private_key.sign(pickle.dumps(message), hashes.SHA256())
                            message = {'signed_message': signed_message, 'plaintext': pickle.dumps(message)}

                            send_msg(users[user],pickle.dumps(message))
                            prev_entry = do_log(users[user], users, prev_entry, message, signed_message)


                        for user in users:
                            if user == 0:
                                continue
                            receive = pickle.loads(recv_msg(users[user]))
                            #print("recebi card do player: " + str(user) + "card:" + str(receive['body']))
                            print(receive)

                            cards[user] = pickle.loads(receive['plaintext'])['body']

                        for user in users:
                            message = {'header': '','method':'cards', 'body': cards}
                            signed_message = private_key.sign(pickle.dumps(message), hashes.SHA256())
                            message = {'signed_message': signed_message, 'plaintext': pickle.dumps(message)}
                            send_msg(users[user],pickle.dumps(message))
                            prev_entry = do_log(clt_socket, users, prev_entry, message, signed_message)

                            print("aqui")
                            if user != 0:

                                receive = pickle.loads(recv_msg(users[user]))
                                receive = pickle.loads(receive['plaintext'])
                                #fazer aqui algo para ver se todos fizeramas coisas bem
                                #consensus += receive['body']
                                print(receive)
                                consensus[user] = receive['body']
                        message = {'header': '','method':'', 'body': consensus}
                        print(message)
                        signed_message = private_key.sign(pickle.dumps(message), hashes.SHA256())
                        message = {'signed_message': signed_message, 'plaintext': pickle.dumps(message)}
                        print(consensus)
                        send_msg(users[0],pickle.dumps(message))
                        prev_entry = do_log(users[0], users, prev_entry, message, signed_message)


                        receive2 = recv_msg(users[0])
                        receive = pickle.loads(receive2)
                        sign = receive['signed_message']
                        receive = pickle.loads(receive['plaintext'])

                        print(receive)
                        players_to_kick = receive['body']

                        if players_to_kick == []:
                            for id in players_to_kick:
                                users[id].close()
                                selector.unregister(users[id])
                                users.pop(id)

                        for user in users:
                            if user == 0:
                                continue
                            message = {'header': '','method':'cards', 'body': players_to_kick}
                            signed_message = private_key.sign(pickle.dumps(message), hashes.SHA256())
                            message = {'signed_message': signed_message, 'plaintext': pickle.dumps(message)}
                            send_msg(users[user],pickle.dumps(message))
                            prev_entry = do_log(users[user], users, prev_entry, message, signed_message)

                        #print('ok chega aqui')


                
                    elif method == 'signed deck':
                        #print('signed deck')
                        prev_entry = do_log(clt_socket, users, prev_entry, "Caller sent a signed deck", sign )

                        message = {'header': '','method': 'shuffle deck', 'originid':0, 'body': body}
                        for user in users:
                            if user == 0:
                                continue
                            
                            soc = users[user]
                            signed_message = private_key.sign(pickle.dumps(message), hashes.SHA256())

                            message = {'signed_message': signed_message, 'plaintext': pickle.dumps(message)}
                            #print(message)
                            send_msg(soc, pickle.dumps(message))
                            prev_entry = do_log(soc, users, prev_entry, message, signed_message)

                            shuffled_deck = pickle.loads(recv_msg(soc))

                            message = {'header': '','method': 'shuffle deck', 'originid':0, 'body': body}


                            message['originid'] = user

                            print(shuffled_deck)
                            
                            message['body'] = pickle.loads(shuffled_deck['plaintext'])['body']
                            if user == len(users)-1:
                                #print("last user")
                                message = {'header': '','method': 'shuffled deck', 'body': message['body']}
                                ##print(message)
                                #print(f'sent shuffled deck, origin {user}')
                                signed_message = private_key.sign(pickle.dumps(message), hashes.SHA256())

                                message = {'signed_message': signed_message, 'plaintext': pickle.dumps(message)}
                                #print(message)
                                send_msg(users[0], pickle.dumps(message))
                                prev_entry = do_log(users[0], users, prev_entry, message, signed_message)


                    elif method == 'last sign':
                        
                        sim_keys = {}
                        #print("last sign")
                        for user in users:
                            soc = users[user]
                            message = {'header': '', 'method':'send sim keys', 'body':body}
                            signed_message = private_key.sign(pickle.dumps(message), hashes.SHA256())

                            message = {'signed_message': signed_message, 'plaintext': pickle.dumps(message)}
                            send_msg(soc, pickle.dumps(message))
                            prev_entry = do_log(soc, users, prev_entry, message, signed_message)

                            
                            receive = pickle.loads(recv_msg(soc))
                            sim_keys[user] = pickle.loads(receive['plaintext'])['body']


                        
                        message = {'header': '', 'method': 'decrypt', 'body':sim_keys}
                        for user in users:
                            message = {'header': '', 'method': 'decrypt', 'body':sim_keys}
                            soc = users[user]
                            if user==0:
                                signed_message = private_key.sign(pickle.dumps(message), hashes.SHA256())

                                message1 = {'signed_message': signed_message, 'plaintext': pickle.dumps(message)}
                                send_msg(soc, pickle.dumps(message1))
                                prev_entry = do_log(soc, users, prev_entry, message, signed_message)

                                receive = pickle.loads(recv_msg(soc))
                                decrypted_deck = pickle.loads(receive['plaintext'])['body']

                            else:
                                signed_message = private_key.sign(pickle.dumps(message), hashes.SHA256())

                                message1 = {'signed_message': signed_message, 'plaintext': pickle.dumps(message)}
                                send_msg(soc, pickle.dumps(message1))
                                prev_entry = do_log(soc, users, prev_entry, message, signed_message)

                                deck = pickle.loads(recv_msg(soc))
                                if decrypted_deck != pickle.loads(deck['plaintext'])['body']:
                                    print("cheater")
                                else:
                                    print("legit")
                                    
                        for user in users:
                            soc = users[user]       
                            message = {'header': '','method':'solution', 'body': ''}
                            signed_message = private_key.sign(pickle.dumps(message), hashes.SHA256())

                            message1 = {'signed_message': signed_message, 'plaintext': pickle.dumps(message)}
                            print("sending to ",user)
                            send_msg(soc,pickle.dumps(message1)) 
                            prev_entry = do_log(soc, users, prev_entry, message, signed_message)

                            receive = pickle.loads(recv_msg(soc))
                            print(receive)

                        receive = pickle.loads(recv_msg(caller_sck))
                        print("players to kick:")
                        if pickle.loads(receive['plaintext'])['body']:
                            #fechar socket
                            for x in pickle.loads(receive['plaintext'])['body']:
                                users[x].close()

                            print("fechar ligação")

                        receive = pickle.loads(recv_msg(caller_sck))
                        print("classificação:")


                                    #envia a solução para os players
                                    # message = {'header': '','method':'solution', 'body': receive['body']}
                                    # for user in users:
                                    #     if user == 0:
                                    #         continue
                                    #     signed_message = private_key.sign(pickle.dumps(message), hashes.SHA256())

                                    #     message1 = {'signed_message': signed_message, 'plaintext': pickle.dumps(message)}
                                    #     send_msg(users[user],pickle.dumps(message1))
                                    #     #receber as classificações de todos os players
                                    #     receive = pickle.loads(recv_msg(users[user]))
                                    #     #print("recebi solução do player: " + str(user) + "solução:" + str(receive['body']))
                                    #     solutions[user] = receive['body']
                                    #     #print("solutions")
                                    #     #print(solutions)
                                    
                                    # #enviar todas as clasificações de todos os players para o caller
                                    # message = {'header': '','method':'ver_solution', 'body': solutions}
                                    # signed_message = private_key.sign(pickle.dumps(message), hashes.SHA256())

                                    # message1 = {'signed_message': signed_message, 'plaintext': pickle.dumps(message)}
                                    # send_msg(caller_sck,pickle.dumps(message1))
                                    # #adicionar algo caso hajam clasificações diferentes 
                                    # #receber a classificação final
                                    # receive = pickle.loads(recv_msg(caller_sck))
                                    #print("classificação:")
                                    #print(receive['body'])
                    
                if header == 'PLAYER':
                    if body == '':
                        print('caller joined. game starts in 20 seconds')

            #print(user_info)




def get_user_list():
    return user_info


def sign_message(message, private_key):

    signature = private_key.sign(
    message,
    padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH
    ),
    hashes.SHA256()
    )

    return signature


def verify_signature(signature,message, public_key):
    return public_key.verify(signature, message, hashes.SHA256())

def cc_verify(signature,message,cc_cert_data):

    cc_cert = x509.load_pem_x509_certificate(cc_cert_data)
    cc_key = cc_cert.public_key()

    md = hashes.Hash(hashes.SHA1())
    md.update(bytes(str(message),'utf-8'))
    digest = md.finalize()

    return cc_key.verify(signature, digest, PKCS1v15(), hashes.SHA1())

def get_seguence(clt,us):
    for key,value in us.items():
        if value == clt:
            return key

# Log the message

def do_log(clt,us,entry,mess,sig):
    sequence = str(get_seguence(clt,us))
    asctime = date_time()
    prev_entry_hash = hashlib.sha256(entry.encode()).hexdigest()
    logging.info(mess, extra={'sequence': sequence,'hash':prev_entry_hash,'signature':sig})
    prev = sequence + "," + asctime + "," + prev_entry_hash + "," + str(mess)
    return prev

def date_time():
    timestamp = time.time()
    return datetime.datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')


def main():
    if len(sys.argv) != 2:
        #print( 'Usage: %s port' % (sys.argv[0]) )
        sys.exit( 1 )

    with socket.socket( socket.AF_INET, socket.SOCK_STREAM ) as s:
        s.bind( ('0.0.0.0', int(sys.argv[1]) ) )
        s.listen()
        dispatch( s )





if __name__ == '__main__':
    main()
