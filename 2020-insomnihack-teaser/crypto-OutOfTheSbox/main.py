#!/usr/bin/python3

from binascii import hexlify
from hashlib import md5
from os import urandom
from random import randint
from re import search
from time import sleep, time

from des import *

WELCOME = 'Brace yourself, your favorite oracle has a challenge for you...'
TASK = 'Can you recover the key?'
WRONG = 'Looks like you can\'t... :('

def pow():
    # Generate PoW
    target = hexlify(urandom(3)).decode()
    print(f'POW: Give me an input whose md5sum starts with "{target}"', flush=True)

    # Veriy PoW
    m = md5()
    m.update(input().encode())
    h = m.hexdigest()
    return h[:6] == target

def welcome():
    # Welcome client
    print(WELCOME, flush=True)
    sleep(randint(0, 3))

def challenge():
    # Generate challenge
    key = int.from_bytes(urandom(6), 'big')
    keys = key_schedule(key)
    data = []
    for i in range(50000):
        plaintext = int.from_bytes(urandom(8), 'big')
        ciphertext = enc(plaintext, keys, sboxs, perms)
        data.append((plaintext, ciphertext))

    # Validate data
    inv_keys = reorder_keys(keys)
    inv_perms = reorder_perms(perms)
    inv_sboxs = reorder_sboxs(sboxs)
    for p, c in data:
        assert(p == enc(c, inv_keys, inv_sboxs, inv_perms))

    # Print challenge
    print(str(data) + '\n', flush=True)

    return key

def reward(start, key):

    # Wait for response
    print(TASK, flush=True)
    response = input()

    # Verify response
    if time() - start < 1337 and \
       len(response.strip()) == 12 and \
       search(r'([0-9A-F]{12})', response) and \
       int(response, 16) == key:

        reward = ''.join(open('/home/ctf/flag.txt', 'r').readlines())
        print(reward, flush=True)
    else:
        print(WRONG, flush=True)

if __name__ == '__main__':
    if pow():
        start = time()
        welcome()
        key = challenge()
        reward(start, key)
