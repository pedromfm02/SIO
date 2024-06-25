#!/bin/python

import sys
import socket
import pickle
import random
import time
import binascii
import base64
import ast

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dsa
from cryptography.hazmat.primitives.asymmetric import dsa
from cryptography.fernet import Fernet

import os
current = os.path.dirname(os.path.realpath('messages.py'))
parent = os.path.dirname(current)
sys.path.append(parent) 
from messages import send_msg, recv_msg, exact_recv

from sign import cc_sign

DECK_LENGTH = 100
CARD_LENGTH = DECK_LENGTH//4 
private_key = dsa.generate_private_key(
    key_size=1024,
)

public_key = private_key.public_key()
users_pub_keys = {}
playing_area_key = None

def verify_playing_area(public_key, signed_text, plaintext):

    public_key.verify(signed_text, plaintext, hashes.SHA256())

def main():
    if len(sys.argv) != 3:
        #print( 'Usage: %s port' % (sys.argv[0]) )
        sys.exit( 1 )

    user_name = sys.argv[1]


    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect( ( '127.0.0.1', int(sys.argv[1]) ) )

        public_key_to_send = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        public_key_to_send.splitlines()[0]

        message = {'header': 'PLAYER', 'body': {'public_key': public_key_to_send, 'username': user_name}}

        signed_message,cc_cert = cc_sign(bytes(str(message),'utf-8'))

        cc_cert_data = cc_cert.public_bytes(encoding=serialization.Encoding.PEM)

        message = {'header':'player','signed message':signed_message, 'plaintext':message, 'cc_cert':cc_cert_data}


        send_msg(s, pickle.dumps( message ))

        received = pickle.loads(recv_msg(s))
        

        playing_area_key = received['public_key']

        user_info_msg = pickle.loads(recv_msg(s))
        #print(user_info_msg)
        playing_area_key_pub = serialization.load_pem_public_key(playing_area_key)
        verify_playing_area(playing_area_key_pub,user_info_msg['signed_message'], user_info_msg['plaintext'])
        user_info_msg = pickle.loads(user_info_msg['plaintext'])
        user_info_msg = user_info_msg['body']

        #print(user_info_msg)
        print(user_info_msg)
        for key,value in user_info_msg.items():
            users_pub_keys[key] = value[1]

        receive = pickle.loads(recv_msg(s))
        print(receive)
        verify_playing_area(playing_area_key_pub,receive['signed_message'],receive['plaintext'])
        receive = pickle.loads(receive['plaintext'])
        print(receive)

        if receive['body'] == 'game started':
            print("jogo começou vou criar o meu cartao")
            card = card_genrator()
            print(card)
            message = {'header': 'PLAYER','method': 'card', 'body': card}

            signed_message = private_key.sign(pickle.dumps(message), hashes.SHA256())

            message = {'signed_message': signed_message, 'plaintext': pickle.dumps(message)}


            send_msg(s, pickle.dumps(message))


        receive = pickle.loads(recv_msg(s))
        verify_playing_area(playing_area_key_pub,receive['signed_message'],receive['plaintext'])
        receive = pickle.loads(receive['plaintext'])

        if receive['method'] == 'cards':
            print("recebi a lista de todos os cartoes")
            #meter aqui uma função que verifica se os cards estão tds certos senão tiverem mandar algum tipo de aviso 
            cards = receive['body']
            print(cards)
            #message = {'header': 'PLAYER', 'body': 1}
            #send_msg(s, pickle.dumps(message))
            cards_ver = ver_card(cards)
            message = {'header': 'PLAYER', 'method': 'num_rep', 'body': cards_ver}
            signed_message = private_key.sign(pickle.dumps(message), hashes.SHA256())
            message = {'signed_message': signed_message, 'plaintext': pickle.dumps(message)}


            send_msg(s, pickle.dumps(message))
            receive = pickle.loads(recv_msg(s))
            verify_playing_area(playing_area_key_pub,receive['signed_message'],receive['plaintext'])
            receive = pickle.loads(receive['plaintext'])
            print(receive)

            players_to_kick = receive['body']
            print(players_to_kick)
            if players_to_kick:
                for k in players_to_kick:
                    print("popping")
                    print(k)
                    #print(users_pub_keys)
                    users_pub_keys.pop(k)
                    cards.pop(k)

        receive = pickle.loads(recv_msg(s))
        print(receive)
        verify_playing_area(playing_area_key_pub,receive['signed_message'], receive['plaintext'])
        receive = pickle.loads(receive['plaintext'])
        signed_deck = receive['body']['signed deck']
        plaintext = receive['body']['plaintext']
        origin_id = receive['originid']

        verify_message(signed_deck, plaintext, origin_id)
        print('verified')




        if receive['method'] == 'shuffle deck':
            
            plaintext,sym_key = shuffle_deck(plaintext)
            signed_deck = sign_message(str(plaintext).encode('utf-8'),private_key)

            receive['body']['signed deck'] = signed_deck
            receive['body']['plaintext'] = plaintext

            signed_message = private_key.sign(pickle.dumps(receive), hashes.SHA256())

            receive = {'signed_message': signed_message, 'plaintext': pickle.dumps(receive)}

            send_msg(s, pickle.dumps(receive))
            

        receive = pickle.loads(recv_msg(s))
        print(receive)
        verify_playing_area(playing_area_key_pub,receive['signed_message'], receive['plaintext'])
        receive = pickle.loads(receive['plaintext'])
        print('ok')

        if receive['method'] == 'send sim keys':
            body = receive['body']
            message = {'header': 'PLAYER','method': 'sym keys', 'body':sym_key}

            signed_message = private_key.sign(pickle.dumps(message), hashes.SHA256())

            message = {'signed_message': signed_message, 'plaintext': pickle.dumps(message)}

            send_msg(s, pickle.dumps(message))

        receive = pickle.loads(recv_msg(s))
        verify_playing_area(playing_area_key_pub,receive['signed_message'], receive['plaintext'])
        receive = pickle.loads(receive['plaintext'])



        if receive['method'] == 'decrypt':
            print('decrypt')
            decrypted_deck = decrypt_deck(body['plaintext'],receive['body'])
            message = {'header': 'caller','method':'decrypted deck', 'body': decrypted_deck}

            signed_message = private_key.sign(pickle.dumps(message), hashes.SHA256())

            message = {'signed_message': signed_message, 'plaintext': pickle.dumps(message)}

            send_msg(s, pickle.dumps(message))
            print("sent")

        print("waiting")
        receive = pickle.loads(recv_msg(s))
        verify_playing_area(playing_area_key_pub,receive['signed_message'], receive['plaintext'])
        receive = pickle.loads(receive['plaintext'])
        if receive['method'] == 'solution':
            print("o gajo quer a classificação")
            ranks = compute(decrypted_deck,cards)
            print("classificação:")
            print(ranks)
            message = {'header': 'PLAYER','method':'final' ,'body': ranks}

            signed_message = private_key.sign(pickle.dumps(message), hashes.SHA256())

            message = {'signed_message': signed_message, 'plaintext': pickle.dumps(message)}
            
            send_msg(s, pickle.dumps(message))
            print("sent ",message)



        for line in sys.stdin:

            message = {'signed_message': signed_message, 'plaintext': pickle.dumps(message)}


            send_msg( s, pickle.dumps( message ))
            

            data = recv_msg( s )
            if data == None:
                 break
            
            data = pickle.loads( data )

        
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
            val = i
        ranks[key] = val

    return ranks


""" returns a random card """
def card_genrator(): 

    nums_bingo = [i+1 for i in range(DECK_LENGTH)]
    # cheat = random.randint(1, 10)
    cheat = 1
    card = []

    for i in range(CARD_LENGTH):

        random.shuffle(nums_bingo)

        if cheat == 8: 
            card.append(nums_bingo[0]) #adicionar mas sem dar pop para que possam haver repetidos
        else:
            card.append(nums_bingo.pop(0))

    return card



def shuffle_deck(deck):

    key = Fernet.generate_key()
    cipher = Fernet(key)
    encrypted_deck = []
    if type(deck) == bytes:
        deck = deck.decode('utf-8')
        my_list = ast.literal_eval(deck)
    else:
        my_list = deck
    

    for number in my_list:
        ##print(type(number))
        encrypted_char = cipher.encrypt(number)
        encrypted_deck.append(encrypted_char)

    random.shuffle(encrypted_deck)
    return encrypted_deck,key 



def decrypt_deck(encrypted_deck,keys):
    #print(encrypted_deck)

    users = list(keys.keys())
    for user in reversed(users):
        cipher = Fernet(keys[user])
        decrypted_deck = []
        for number in encrypted_deck:
            #print(type(number))
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

def verify_message(message, plaintext, origin_id):

    if type(plaintext) != bytes:
        plaintext = str(plaintext).encode('utf-8')

    public_key = users_pub_keys[origin_id]



    public_key = serialization.load_pem_public_key(public_key)


    public_key.verify(message,plaintext,hashes.SHA256())




if __name__ == '__main__':
    main()
