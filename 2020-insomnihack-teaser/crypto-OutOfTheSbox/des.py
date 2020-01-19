import numpy as np

from params import *

N = 256
ROUNDS = 7

def key_schedule(key):
    keys = []
    for i in range(ROUNDS):
        left = (key >> (16*((i+1) % 3))) & 0x0000FFFF;
        right = (key >> (16*(i%3))) & 0x0000FFFF;

        keys.append((left << 16) | right);

    return keys

def reorder_keys(keys):
    inv = list(keys)
    inv.reverse()

    return inv

def reorder_perms(perms):
    inv = list(perms)
    inv.reverse()

    return inv

def reorder_sboxs(sboxs):
    inv = np.zeros((ROUNDS, 4, N))
    for i in range(ROUNDS):
        for j in range(4):
            inv[ROUNDS - 1 - i,j] = sboxs[i,j,:]

    return inv

def apply_perm32(perm, x):
    out = 0
    for i in range(32):
        out |= ((x & (0x00000001 << i)) >> i) << (perm[i])

    return out

def fbox(x, key, sboxs, perm):
    tmp = x ^ key

    tmp = int(sboxs[0, 0x000000FF & tmp]) | int(sboxs[1, (0x0000FF00 & tmp) >> 8]) << 8 | int(sboxs[2, (0x00FF0000 & tmp) >> 16]) << 16 | int(sboxs[3, (0xFF000000 & tmp) >> 24]) << 24
    out = apply_perm32(perm, tmp);

    return out;

def enc(plaintext, keys, sboxs, perms):
    A = plaintext & 0xFFFFFFFF
    B = plaintext >> 32

    for i in range(ROUNDS):
        y = fbox(A, keys[i], sboxs[i], perms[i])
        tmp = B ^ y
        B = A
        A = tmp

    return A << 32 | B
