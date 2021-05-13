from bitstring import BitArray
import base64
from pwn import *
import getopt
import sys
import string

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
        score += hammingDistance(data[slice_1], data[slice_2])
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
    for i in range(0xff):
        key = chr(i).encode()
        attempt = xorBytes(data, key * len(data))
        score = scoreLetters(attempt)
        if score > best_score:
            best_score = score
            best_key = key
    return best_key

def attackOnKeysize(data, keysize):
    chunks = [data[i::keysize] for i in range(keysize)]
    final_key = b''.join([xorSingleByteBruteforce(chunk) for chunk in chunks])
    return {"key":final_key, "result":xorBytes(data, final_key)}

def attack(data, keysize_min, keysize_max):
    score = 0
    best_obj = {"key":b'', "result":b''}
    p = log.progress("Working on ")
    for i in range(keysize_min+1, keysize_max+1):
        p.status("keysizes-range {}=>{}...".format(keysize_min, i))
        keysize = probableKeysize(data, keysize_min, i)
        obj_result = attackOnKeysize(data, keysize)
        tmp_score = scoreLetters(obj_result["result"])
        if tmp_score > score:
            score = tmp_score
            best_obj = obj_result
    return best_obj

def usage():
    print("""Usage of XOR Breaker :
    Example : 
    {} --min 1 --max 10 --type text "OgwQEVQWGxsARVJULQoGVBwEBRFUARwaEUUEERgJUwAcDABUER0SGQQJFlRV"

    -h : Print the current help

    -m/--min (optional | default: 2)
        -> set the minimum keysize

    -M/--max (optional | default: 80)
        -> set the maximum keysize
    
    -t/--type (optional | default: file | values : file,text)
        ->  set the type of input you give. 
            It can be a file, or a text between quotes.
            In case it's a text, it must be base64 encoded.
    """.format(sys.argv[0]))

def main():
    keysize_min = 2
    keysize_max = 80
    src_type = "file"
    src = null
    try:
        opts, args = getopt.getopt(sys.argv[1:], "hm:M:t:", ["help", "min=", "max=", "type="])
        for o, a in opts:
            if o in ("-h", "--help"):
                usage()
                sys.exit()
            elif o in ("-m", "--min"):
                keysize_min = int(a)
            elif o in ("-M", "--max"):
                keysize_max = int(a)
            elif o in ("-t", "--type"):
                if a not in ("text", "file"):
                    raise Exception("Misuse")
                src_type = a
            else:
                assert False, "unhandled option"
        
        if len(args) != 1:
            raise Exception("Source missing or too much arguments !")
        if keysize_min > keysize_max:
            raise Exception("Keysize_min > Keysize_max !")
        src = args[0]
    except Exception as exc:
        print(exc.args[0])
        usage()
        sys.exit(2)
    except getopt.GetoptError as err:
        print(err)
        usage()
        sys.exit(2)


    if src_type == "file":
        ciphertext= open(src, 'r').read()
    else:
        ciphertext = src
    raw_data = base64.b64decode(ciphertext)
    keysize_max = min(keysize_max, len(raw_data)//2)
    print("Datas read length : {}".format(len(raw_data)))
    found_result = attack(raw_data, keysize_min, keysize_max)
    print("With the key (length {}) <{}>".format(len(found_result["key"]),found_result["key"]))
    print("Result (first 500 bytes) :\n\n{}".format(found_result["result"][:500].decode()))

if __name__ == "__main__":
    main()
