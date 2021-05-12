from bitstring import BitArray
import base64
from pprint import pprint
import numpy as np
from pwn import *
import itertools
import sys

def score_frequences(text):
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
    score = 0
    uniform_text = bytes(text).decode().upper()
    c_count = 0
    for c in bytes(text).decode().upper():
        if c in frequences:
            score += frequences[c]
        if c != " ":
            c_count += 1
    return score / c_count

def bytes_to_bin(datas):
    if type(datas) == str:
        datas = datas.encode()
    return BitArray(bytes=datas).bin

def hammingDistance(datas, keysize, chunk_count = 2):
    ar_chunks = []
    for i in range(chunk_count):
        chunk = bytes_to_bin(datas[i*keysize:(i+1)*keysize])    
        chunk = [int(c) for c in chunk]
        ar_chunks.append(chunk)
    ar_chunks_transposed = np.array(ar_chunks).transpose()
    hamming_bytes_invert = [all(chunk[0] == x for x in chunk) for chunk in ar_chunks_transposed]
    hamming_bytes = [i==0 for i in hamming_bytes_invert]
    return sum(hamming_bytes)

def hammingDistanceNormalized(datas, keysize, chunk_count=2):
    return hammingDistance(datas, keysize, chunk_count) / keysize

def xor_single_bruteforce(encoded):
    printable = string.printable.encode()
    possibles_keys = []
    for i in range(0xff):
        attempt = b''.join([chr(i^c).encode() for c in b''.join(encoded)])
        if all([c in printable for c in attempt]):
            possibles_keys.append(i)
    return possibles_keys

def attack_by_keysize(datas, keysize):
    print("Attacking on keysized", str(keysize))
    if type(datas) == str:
        datas = datas.encode()
    ar_chunks = [ [chr(c).encode() for c in datas[i:i+keysize]] for i in range(0, keysize*(len(datas)//keysize), keysize) ]
    ar_chunks_transposed = np.array(ar_chunks).transpose()
    probables_keys_for_combination = []
    for i in range(len(ar_chunks_transposed)): #len() == keysize. so chunk_1 => key[0]
        print("Chunk {} : {}".format(i, b''.join(ar_chunks_transposed[i]).hex()))
        probables_keys = xor_single_bruteforce(ar_chunks_transposed[i])
        keys_scores = {}
        for pk in probables_keys:
            xored_value = xor(b''.join(ar_chunks_transposed[i]), chr(pk).encode())
            key_score = score_frequences(xored_value)
            keys_scores[str(pk)] = key_score
        keys_scores_sorted = sorted(keys_scores.items(), key=lambda x: x[1], reverse=True)
        if len(keys_scores_sorted) == 0:
            return
        for j in range(min(len(keys_scores_sorted), 10)):
            pk = int(keys_scores_sorted[j][0])
            xored_value = xor(b''.join(ar_chunks_transposed[i]), pk)
            print("Keysize {} : Position {} : Key : {} ({}) : Score : {} => {}".format(keysize, i, pk, chr(pk).encode(), round(keys_scores_sorted[j][1],3), xored_value))
        checked_keys = input("What keys do seem probables ? (comma delimited, int -> 102,104, ...) (-1 to skip) > ").strip().split(',')
        print(checked_keys, len(checked_keys))
        if checked_keys[0] == '':
            checked_keys.pop()
            for x in range(min(len(keys_scores_sorted),3)):
                checked_keys.append(keys_scores_sorted[x][0])
        checked_keys = [int(x) for x in checked_keys]
        if -1 in checked_keys:
            return
        probables_keys_for_combination.append(checked_keys)

    print("For keysize {},".format(keysize))
    combinations = list(itertools.product(*probables_keys_for_combination))
    [ ''.join([str(i) for i in k]) for k in combinations]
    print("There is {} possibilities".format(len(list(itertools.product(*probables_keys_for_combination)))))
    results = {}
    for c in combinations:
        combination = b''.join([chr(key_part).encode() for key_part in c])
        xored_result = xor(datas, combination)
        xored_result_score = round(score_frequences(xored_result),3)
        results[(combination, xored_result[:100])] = xored_result_score

    results_sorted = sorted(results.items(), key=lambda x: x[1])
    for i in range(max(0, len(results_sorted)-20), len(results_sorted)):
        combination = results_sorted[i][0][0]
        score = results_sorted[i][1]
        xored_value = results_sorted[i][0][1]
        print("[hex] {} ({}): Score : {} => {}".format(combination.hex(), combination, score, xored_value))


datas = base64.b64decode(open(sys.argv[1], 'r').read())

hammings_norm = {}
for i in range(2,10):
    hammings_norm[str(i)] = hammingDistanceNormalized(datas, i)
    print("Keysize : {} ; score : {}".format(i, hammings_norm[str(i)]))

sorted_hamming = sorted(hammings_norm.items(), key=lambda x: x[1])
keysizes = []
for i in range(min(len(sorted_hamming), 10)):
    item = sorted_hamming[i]
    keysizes.append(int(item[0]))

for keysize in keysizes:
    attack_by_keysize(datas[:200], keysize)
