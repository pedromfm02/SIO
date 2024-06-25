|    Authors    | nº mec |
| ------------- |:------:|
| Filipe Antão  | 103470 |
| Pedro Matos   | 102993 |
| Nuno Sousa    | 103664 |
| Simão Antunes | 104092 |

[![Open in Visual Studio Code](https://classroom.github.com/assets/open-in-vscode-c66648af7eb3fe8bc4f294546bfd86ef473780cde1dea487d3c4ff354943c9ae.svg)](https://classroom.github.com/online_ide?assignment_repo_id=9665657&assignment_repo_type=AssignmentRepo)

---

# Secure Game - Bingo

## Introduction

This report explains the implementation of the player(s) and server network for handling a distributed bingo game.
#### Files:
- player.py
- sign.py
- caller.py
- parea.py
- card.py

---

## How the game works

- The playing area must be the first thing to be initialized.
```python
python3 parea.py [port]
```

- The caller must be the first one to connect to the playing area 
```python
python3 caller.py [port]
```
and then the  players are added to the game,
```python
    python3 player.py [port] [name] [cheat]
```

each of them having an id, a public key and a username.

- Then, the caller must write START on the console for the game to begin:

    - The player creates its own card,
    ```python
    if receive['body'] == 'game started':
            print("jogo começou vou criar o meu cartao")
            card = card_genrator()
            print(card)
            message = {'header': 'PLAYER','method': 'card', 'body': card}

            signed_message = private_key.sign(pickle.dumps(message), hashes.SHA256())

            message = {'signed_message': signed_message, 'plaintext': pickle.dumps(message)}


            send_msg(s, pickle.dumps(message))
    ```
    the caller receives it and verifies if it is a valid card (no cheating or missbehaving)
    ```python
            if receive['method'] == 'cards':
            #meter aqui uma função que verifica se os cards estão tds certos senão tiverem mandar algum tipo de aviso 
            print("recebi os cards")
            cards = receive['body']
            #print(cards)
            cards_ver = ver_card(cards)
            print(cards_ver)
    ```


    - The caller creates the deck, shuffles, encrypts it number by number and sends it to the playing area:
```python
        playing_deck,sim_key = generate_deck()
        signed_deck = sign_message(str(playing_deck).encode('utf-8'),private_key)
        message = {'header': 'CALLER','method': 'signed deck', 'body': {'signed deck': signed_deck, 'plaintext': str(playing_deck).encode('utf-8')}}

        signed_message = private_key.sign(pickle.dumps(message), hashes.SHA256())

        message = {'signed_message': signed_message, 'plaintext': pickle.dumps(message)}

        send_msg(s, pickle.dumps( message ))
```


- The playing area sends the deck to the first player. This player shuffles it again and encrypts it number by number, creating another level of encryption. This deck returns to the playing area and it is sent to the next player and this happens continuosly until the deck has passed through all the players:
```python
elif method == 'signed deck':
                        #print('signed deck')
                        prev_entry = do_log(clt_socket, users, prev_entry, "Caller sent a signed deck")

                        message = {'header': '','method': 'shuffle deck', 'originid':0, 'body': body}
                        for user in users:
                            if user == 0:
                                continue
                            
                            soc = users[user]
                            signed_message = private_key.sign(pickle.dumps(message), hashes.SHA256())

                            message = {'signed_message': signed_message, 'plaintext': pickle.dumps(message)}
                            #print(message)
                            send_msg(soc, pickle.dumps(message))
                            shuffled_deck = pickle.loads(recv_msg(soc))        
```


- The caller receives the final deck, signs it and sends it to the playing area.
```python
if data['method'] == 'shuffled deck':
            print("shuffled deck")
            plaintext = data['body']['plaintext']
            signed_message = sign_message(str(plaintext).encode('utf-8'),private_key)
            message = {'header':'CALLER', 'method': 'last sign', 'body':{'signed message': signed_message, 'plaintext': plaintext}}
            
            signed_message = private_key.sign(pickle.dumps(message), hashes.SHA256())

            message = {'signed_message': signed_message, 'plaintext': pickle.dumps(message)}
            
            send_msg(s, pickle.dumps(message))
```


- The playing area sends this final deck to all the players.
```python
for user in users:
    if user == 0:
        continue
                            
    soc = users[user]
    signed_message = private_key.sign(pickle.dumps(message), hashes.SHA256())

    message = {'signed_message': signed_message, 'plaintext': pickle.dumps(message)}
    #print(message)
    send_msg(soc, pickle.dumps(message))
    shuffled_deck = pickle.loads(recv_msg(soc))

    message = {'header': '','method': 'shuffle deck', 'originid':0, 'body': body}


    message['originid'] = user

    print(shuffled_deck)
```

- At this stage of the game, all the players and the caller calculate the result and the players send it to the playing area.

- The playing area sends all the results to the caller. Then, the caller verifies if these players' results are the same as its own result. If this is true, the caller sends the result to the playing area. Otherwise, the players who provided a wrong result are disqualified and kicked from the game. After that, the caller sends the final result to the playing area.
```python
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
```

---

## Other Functions

Function used by the player to create its own card:
```python
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
```

Function used by the caller to create a deck:
```python
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
```


The signatures are generated by SHA-256:

```python
def sign_message(message,private_key):
    signature = private_key.sign(
    message,
    hashes.SHA256()
)
    return signature
```

The algorithm used for the citizen card signature was RSA. 

DSA algorithm was used in all of the other signatures.


This function calculates the classification of every player card in the game
```python
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
```

Function used by the caller to verify if all the player cards alre valid
```python
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
```

Function used to log the messages

```python
def do_log(clt,us,entry,mess):
    sequence = str(get_seguence(clt,us))
    asctime = date_time()
    prev_entry_hash = hashlib.sha256(entry.encode()).hexdigest()
    logging.info(mess, extra={'sequence': sequence,'hash':prev_entry_hash})
    prev = sequence + "," + asctime + "," + prev_entry_hash + "," + mess
    return prev
```

---

## Cheating and Missbehaving

Cheating happens when a player intentionally subverts rules in order to obtain unfair advantages by, for example, having repeated numbers on their bingo card.

Missbehaving happens when the game unintentionally changes information and it makes the game not work as it is supposed to.

Unfortunatelly, we couldn't implement this part on our project.

---


## Conclusion

Overall, the Secure Game project has given us a better ideia on how to conjugate sockets with security.