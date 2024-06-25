#!/bin/python

import sys
import socket
import pickle
import pickle
import random
import time
import selectors

import fcntl
import os
import sys

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dsa

import os
current = os.path.dirname(os.path.realpath('messages.py'))
parent = os.path.dirname(current)
sys.path.append(parent)
from messages import send_msg, recv_msg, exact_recv

from sign import cc_sign


DECK_LENGTH = 100

private_key = dsa.generate_private_key(
    key_size=1024,
)

public_key = private_key.public_key()

playing_area_key_pem = None

users={}
sel = selectors.DefaultSelector()


def loop(self):
    print(f"{self.username} connected successfully")
    
    while True:
        sys.stdout.flush()
        for key, mask in self.sel.select():
            callback = key.data
            callback(key.fileobj,mask)

def get_input(stdin):
    message=stdin.read()
    
    return message


def verify_message(public_key, signed_text, plaintext):

    public_key.verify(signed_text, plaintext, hashes.SHA256())



def get_socket(cSock,playing_area_key):
    data = pickle.loads(recv_msg(cSock))

    playing_area_key_pub = serialization.load_pem_public_key(playing_area_key)

    verify_message(playing_area_key_pub,data['signed_message'], data['plaintext'])

    data = pickle.loads(data['plaintext'])
    if data['header'] == 'PAREA':
        print('player public key and username received')
        username = data['body']['username']
        id = data['body']['player_id']
        pub_key = data['body']['pub_key']
        
        a = str(username)+str(id)+str(pub_key)
        signed_message = sign_message(str(a).encode('utf-8'),private_key)
        
        #message = { 'header': 'CALLER', 'method': 'return_parea','body':{'signed_message':signed_message, 'plaintext':a}}
        #send_msg(cSock, pickle.dumps(message))
        print("caller signed player info sent")
        

    return data

def main():
    if len(sys.argv) != 2:
        print( 'Usage: %s port' % (sys.argv[0]) )
        sys.exit( 1 )

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect( ( '127.0.0.1', int(sys.argv[1]) ) )
        #s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVTIMEO, 1)
        sel.register(s, selectors.EVENT_READ, get_socket)


        public_key_to_send = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        public_key_to_send.splitlines()[0]


        message = {'header': 'CALLER', 'method': '', 'body': {'public_key': public_key_to_send, 'username': 'manel'}}

        signed_message,cc_cert = cc_sign(bytes(str(message),'utf-8'))

        cc_cert_data = cc_cert.public_bytes(encoding=serialization.Encoding.PEM)

        message = {'header':'CALLER','signed message':signed_message, 'plaintext':message, 'cc_cert':cc_cert_data}
        
        send_msg( s, pickle.dumps( message ) )

        received = pickle.loads(recv_msg(s))

        if 'method' in received:
            if received['method']== "Can't authenticate":
                return 0

        playing_area_key_pem = received['public_key']

        orig_fl = fcntl.fcntl(sys.stdin, fcntl.F_GETFL)
        fcntl.fcntl(sys.stdin, fcntl.F_SETFL, orig_fl | os.O_NONBLOCK)
        sel.register(sys.stdin, selectors.EVENT_READ, get_input)
        while True:
            sys.stdout.flush()
            for key, mask in sel.select():
                callback = key.data
                if callback == get_socket:
                    message = callback(key.fileobj, playing_area_key_pem)
                else:
                    message = callback(key.fileobj)
                if message== "START\n":
                    break
            
            if message == "START\n":
                break
        
        print('vai a sua vida')

        message = { 'header': 'CALLER', 'method': 'close playing area', 'body':'' }

        signed_message = private_key.sign(pickle.dumps(message), hashes.SHA256())

        message = {'signed_message': signed_message, 'plaintext': pickle.dumps(message)}

        send_msg( s, pickle.dumps( message ) )

        """alterado"""
        data = pickle.loads(recv_msg(s))
        playing_area_key_pub = serialization.load_pem_public_key(playing_area_key_pem)
        verify_message(playing_area_key_pub,data['signed_message'], data['plaintext'])
        receive = pickle.loads(data['plaintext'])
        print(receive)

        if receive['method'] == 'cards':
            #meter aqui uma função que verifica se os cards estão tds certos senão tiverem mandar algum tipo de aviso 
            print("recebi os cards")
            cards = receive['body']
            #print(cards)
            cards_ver = ver_card(cards)
            print(cards_ver)
            #message = {'header': 'PLAYER','method': 'num_rep', 'body': cards_ver}
            #send_msg(s, pickle.dumps(message))
            receive = pickle.loads(recv_msg(s))
            verify_message(playing_area_key_pub,receive['signed_message'], receive['plaintext'])
            receive = pickle.loads(receive['plaintext'])
            print(receive)
            cards_ver_players = receive['body']
            print(cards_ver_players)
            print('aqui')
            players_to_kick = []
            for k,y in cards_ver_players.items():
                if y == cards_ver:
                    continue
                else:
                    players_to_kick.append(k)

            for key, value in cards_ver.items():
                if value:
                    if not key in players_to_kick:
                        players_to_kick.append(k)

            message = {'header': 'CALLER', 'method': 'kick', 'body': players_to_kick}

            signed_message = private_key.sign(pickle.dumps(message), hashes.SHA256())

            message = {'signed_message': signed_message, 'plaintext': pickle.dumps(message)}


            print(message)
            send_msg(s, pickle.dumps(message))

            if players_to_kick:
               for players in players_to_kick:
                    #users.pop(players)
                    cards.pop(players)

            print('acabou')


        playing_deck,sim_key = generate_deck()
        signed_deck = sign_message(str(playing_deck).encode('utf-8'),private_key)
        message = {'header': 'CALLER','method': 'signed deck', 'body': {'signed deck': signed_deck, 'plaintext': str(playing_deck).encode('utf-8')}}

        signed_message = private_key.sign(pickle.dumps(message), hashes.SHA256())

        message = {'signed_message': signed_message, 'plaintext': pickle.dumps(message)}

        send_msg(s, pickle.dumps( message ))

        

            #message = {'header': 'CALLER', 'body': 1}
            #send_msg(s, pickle.dumps(message))
        """   """
        

        data = recv_msg(s)
        data = pickle.loads(data)
        #print(data)
        playing_area_key_pub = serialization.load_pem_public_key(playing_area_key_pem)
        verify_message(playing_area_key_pub,data['signed_message'], data['plaintext'])
        data = pickle.loads(data['plaintext'])

        if data['method'] == 'shuffled deck':
            print("shuffled deck")
            plaintext = data['body']['plaintext']
            signed_message = sign_message(str(plaintext).encode('utf-8'),private_key)
            message = {'header':'CALLER', 'method': 'last sign', 'body':{'signed message': signed_message, 'plaintext': plaintext}}
            
            signed_message = private_key.sign(pickle.dumps(message), hashes.SHA256())

            message = {'signed_message': signed_message, 'plaintext': pickle.dumps(message)}
            
            send_msg(s, pickle.dumps(message))



        receive = pickle.loads(recv_msg(s))
        playing_area_key_pub = serialization.load_pem_public_key(playing_area_key_pem)
        verify_message(playing_area_key_pub,receive['signed_message'], receive['plaintext'])

        receive = pickle.loads(receive['plaintext'])

        if receive['method'] == 'send sim keys':
            print("send sim keys")
            message = {'header': 'PLAYER', 'method': 'sym key','body':sim_key}
            last_deck = receive['body']['plaintext']

            signed_message = private_key.sign(pickle.dumps(message), hashes.SHA256())

            message = {'signed_message': signed_message, 'plaintext': pickle.dumps(message)}
            send_msg(s, pickle.dumps(message))

            # data = pickle.loads( data )

        receive = pickle.loads(recv_msg(s))
        playing_area_key_pub = serialization.load_pem_public_key(playing_area_key_pem)
        #print(receive)
        verify_message(playing_area_key_pub,receive['signed_message'], receive['plaintext'])

        receive = pickle.loads(receive['plaintext'])
        if receive['method'] == 'decrypt':
            print("decrypt")
            #print(receive['body'])
            decrypted_deck = decrypt_deck(last_deck,receive['body'])
            message = {'header': 'caller','method':'decrypted deck', 'body': decrypted_deck}

            signed_message = private_key.sign(pickle.dumps(message), hashes.SHA256())

            message = {'signed_message': signed_message, 'plaintext': pickle.dumps(message)}
            send_msg(s, pickle.dumps(message))
        

        """alterado"""
        #print("205")
        receive = pickle.loads(recv_msg(s))
        playing_area_key_pub = serialization.load_pem_public_key(playing_area_key_pem)
        verify_message(playing_area_key_pub,receive['signed_message'], receive['plaintext'])
        receive = pickle.loads(receive['plaintext'])
        #print("\n\n")
        #print(receive)
        if receive['method'] == 'solution':
            #mdevolver o deck que será utilizado como solução
            print("tao me a pedir a solução")
            solution = decrypted_deck
            #print(solution)
            message = {'header': 'PLAYER','method': 'solution', 'body': solution}
            signed_message = private_key.sign(pickle.dumps(message), hashes.SHA256())

            message = {'signed_message': signed_message, 'plaintext': pickle.dumps(message)}
            send_msg(s, pickle.dumps(message))
            rank = compute(solution,cards)
            print("calculei as classificações")
            print(rank)
        """ """

        """alterado"""
        receive = pickle.loads(recv_msg(s))
        if receive['method'] == 'ver_solution':
            #mdevolver o deck que será utilizado como solução
            print("recebi as soluçoes dos players")
            players_class = receive['body']
            #print(players_class)


            players_to_kick = []
            for x, y in players_class.items():
                if y == rank:
                    continue
                else:
                    print("ERRO")
                    players_to_kick.append(x)
                    #falta a parea receber este id (x) e kicka-lo

            message = {'header': 'CALLER', 'method': 'kick', 'body':players_to_kick}
            signed_message = private_key.sign(pickle.dumps(message), hashes.SHA256())

            message = {'signed_message': signed_message, 'plaintext': pickle.dumps(message)}
            send_msg(s, pickle.dumps(message))

            
            message = {'header': 'PLAYER', 'body': rank}
            signed_message = private_key.sign(pickle.dumps(message), hashes.SHA256())

            message = {'signed_message': signed_message, 'plaintext': pickle.dumps(message)}
            send_msg(s, pickle.dumps(message))
        """ """


def compute(deck,cards):
    ranks = {}
    deck_clean = []
    for val in deck:
        deck_clean.append(int(val))
    print(deck_clean)
    for key,value in cards.items():
        print(key,value)
        val = 0
        for i in range(len(deck_clean)):
            if deck_clean[i] in value:
                value.remove(deck_clean[i])
            if value == []:
                val = i + 1
                print(val)
                break
        ranks[key] = val

    return ranks


def generate_deck():
    deck = [i+1 for i in range(DECK_LENGTH)]
    encrypted_deck = []

    random.shuffle(deck)
    
    #print(deck)

    key = Fernet.generate_key()
    cipher = Fernet(key)
    
    for number in deck:
        #print(type(number))
        encrypted_char = cipher.encrypt(bytes(str(number),'utf-8'))
        encrypted_deck.append(encrypted_char)
    

    return encrypted_deck,key

def ver_card(cards):
    ver_dic = {}
    for key in cards:
        counter = {}
        for x in cards[key]:
            if x in counter:
                counter[x] += 1
            else:
                counter[x] = 1
        for counter_key in counter:
            if counter[counter_key] > 1:
                ver_dic[key] = True
            else:
                ver_dic[key] = False
    return ver_dic


def decrypt_deck(encrypted_deck,keys):

    users = list(keys.keys())
    for user in reversed(users):
        cipher = Fernet(keys[user])
        decrypted_deck = []
        for number in encrypted_deck:
            decrypted_char = cipher.decrypt(number)
            decrypted_deck.append(decrypted_char)
        encrypted_deck = decrypted_deck

    return decrypted_deck


def sign_message(message,private_key):
    signature = private_key.sign(
    message,
    hashes.SHA256()
)
    return signature


if __name__ == '__main__':
    main()
