from bitstring import BitArray
import base64
from pwn import *
import itertools
import sys
import string

def scoreFrequencies(data):
    frequences = {}
    frequences["A"] = 8.08
    frequences["B"] = 1.67
    frequences["C"] = 3.18
    frequences["D"] = 3.99
    frequences["E"] = 12.56
    frequences["F"] = 2.17
    frequences["G"] = 1.80
    frequences["H"] = 5.27
    frequences["I"] = 7.24
    frequences["J"] = 0.14
    frequences["K"] = 0.63
    frequences["L"] = 4.04
    frequences["M"] = 2.60
    frequences["N"] = 7.38
    frequences["O"] = 7.47
    frequences["P"] = 1.91
    frequences["Q"] = 0.09
    frequences["R"] = 6.42
    frequences["S"] = 6.59
    frequences["T"] = 9.15
    frequences["U"] = 2.79
    frequences["V"] = 1.00
    frequences["W"] = 1.89
    frequences["X"] = 0.21
    frequences["Y"] = 1.65
    frequences["Z"] = 0.07
    score = sum([frequences[c] for c in data.decode().upper() if c in frequences])
    return score / len(data) 

def scoreLetters(data):
    letters = (string.ascii_letters + " ").encode()
    return sum([x in letters for x in data]) / len(data)

def forceToBytes(text):
    if type(text) == str:
        text = text.encode()
    return text

def bytesToBin(data):
    return BitArray(bytes=force_to_bytes(data)).bin

def xorBytes(b1, b2):
    s1 = b1
    s2 = b2
    if len(s2) < len(s1):    
        s2 = (s2 * (len(s1) // len(s2) +1))[:len(s1)]
    return bytes([i^j for (i,j) in zip(s1, s2)])

def hammingDistance(b1, b2):
    return [bin(i).count('1') for i in xorBytes(b1, b2)][0]

def keysizeScore(data, keysize):
    nb_calc = len(data) // keysize -1
    score = 0
    for i in range(nb_calc):
        slice_1 = slice(keysize*i, keysize*(i+1))
        slice_2= slice(keysize*(i+1), keysize*(i+2))
        part_1 = data[slice_1]
        part_2 = data[slice_2]
        score += hammingDistance(part_1, part_2)
    score /= keysize
    score /= nb_calc
    return score

def probableKeysize(data, keysize_min, keysize_max):
    score = 1000000
    probable_keysize = -1
    for i in range(keysize_min, keysize_max):
        tmp_score = keysizeScore(data, i)
        if tmp_score < score:
            score = tmp_score
            probable_keysize = i
    return probable_keysize

def xorSingleByteBruteforce(data):
    printable = string.printable.encode()
    best_key = b''
    best_score = 0
    best_message = b""
    for i in range(0xff):
        key = chr(i).encode()
        attempt = xorBytes(data, key * len(data))
        if True: #all([c in printable for c in attempt]):
            score = scoreLetters(attempt)
            if score > best_score:
                best_score = score
                best_key = key
                best_message = attempt
    return best_key

def attack(data):
    keysize = probableKeysize(raw_data, keysize_min, keysize_max)
    print("Attacking on keysized", str(keysize))
    chunks = [data[i::keysize] for i in range(keysize)]
    final_key = b''
    for chunk in chunks:
#        print("Chunk : {}".format(chunk))
        final_key += xorSingleByteBruteforce(chunk)
    print("Key found : {}".format(final_key))
    return xorBytes(data, final_key)

keysize_min = 2
keysize_max = 40

if len(sys.argv) < 2:
    print("No file specified")
    exit()
ciphertext= open(sys.argv[1], 'r').read()
raw_data = base64.b64decode(ciphertext)

if len(sys.argv) == 3:
    print("Require min AND max keysize guessing")
    exit()
if len(sys.argv) == 4:
    keysize_min = int(sys.argv[2])
    keysize_max = int(sys.argv[3])
keysize_max = min(keysize_max, len(raw_data)//2)
print("Datas read length : {}".format(len(raw_data)))


result = attack(raw_data)
print(result.decode()[:200])
