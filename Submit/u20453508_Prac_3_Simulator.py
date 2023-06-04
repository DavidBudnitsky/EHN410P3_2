# David Budnitsky
# 20453508

from u20453508_Prac_3_Backend import *
import numpy as np
import string
from PIL import Image

# These values are from https://stackoverflow.com/questions/287871/how-do-i-print-colored-text-to-the-terminal
HEADER = '\033[95m'
OKBLUE = '\033[94m'
OKCYAN = '\033[96m'
OKGREEN = '\033[92m'
WARNING = '\033[93m'
FAIL = '\033[91m'
ENDC = '\033[0m'
BOLD = '\033[1m'
UNDERLINE = '\033[4m'

np.set_printoptions(threshold=np.inf)

stringPrintable = string.printable[0:94]
line = "-" * 13
smallPrimes = [31, 37, 41, 43, 47, 53, 59, 61, 67, 71,
               73, 79, 83, 89, 97, 101, 103, 107, 109, 113,
               127, 131, 137, 139, 149, 151, 157, 163, 167, 173,
               179, 181, 191, 193, 197, 199, 211, 223, 227, 229,
               233, 239, 241, 251, 257, 263, 269, 271, 277, 281,
               283, 293, 307, 311, 313, 317, 331, 337, 347, 349,
               353, 359, 367, 373, 379, 383, 389, 397, 401, 409,
               419, 421, 431, 433, 439, 443, 449, 457, 461, 463,
               467, 479, 487, 491, 499, 503, 509, 521, 523, 541,
               547, 557, 563, 569, 571, 577, 587, 593, 599, 601,
               607, 613, 617, 619, 631, 641, 643, 647, 653, 659,
               661, 673, 677, 683, 691, 701, 709, 719, 727, 733,
               739, 743, 751, 757, 761, 769, 773, 787, 797, 809,
               811, 821, 823, 827, 829, 839, 853, 857, 859, 863,
               877, 881, 883, 887, 907, 911, 919, 929, 937, 941,
               947, 953, 967, 971, 977, 983, 991, 997]
bigPrimes = [1009, 1013,
             1019, 1021, 1031, 1033, 1039, 1049, 1051, 1061, 1063, 1069,
             1087, 1091, 1093, 1097, 1103, 1109, 1117, 1123, 1129, 1151,
             1153, 1163, 1171, 1181, 1187, 1193, 1201, 1213, 1217, 1223,
             1223, 1229, 1231, 1237, 1249, 1259, 1277, 1279, 1283, 1289,
             1291, 1297, 1301, 1303, 1307, 1319, 1321, 1327, 1361, 1367,
             1373, 1381, 1399, 1409, 1423, 1427, 1429, 1433, 1439, 1447,
             1451, 1453, 1459, 1471, 1481, 1483, 1487, 1489, 1493, 1499,
             1511, 1523, 1531, 1543, 1549, 1553, 1559, 1567, 1571, 1579,
             1583, 1597, 1601, 1607, 1609, 1613, 1619, 1621, 1627, 1637,
             1657, 1663, 1667, 1669, 1693, 1697, 1699, 1709, 1721, 1723,
             1733, 1741, 1747, 1753, 1759, 1777, 1783, 1787, 1789, 1801,
             1811, 1823, 1831, 1847, 1861, 1867, 1871, 1873, 1877, 1879,
             1889, 1901, 1907, 1913, 1931, 1933, 1949, 1951, 1973, 1979,
             1987, 1993, 1997, 1999, 2003, 2011, 2017, 2027, 2029, 2039,
             2053, 2063, 2069, 2081, 2083, 2087, 2089, 2099, 2111, 2113,
             2129, 2131, 2137, 2141, 2143, 2153, 2161, 2179, 2203, 2207,
             2213, 2221, 2237, 2239, 2243, 2251, 2267, 2269, 2273, 2281,
             2287, 2293, 2297, 2309, 2311, 2333, 2339, 2341, 2347, 2351,
             2357, 2371, 2377, 2381, 2383, 2389, 2393, 2399, 2411, 2417,
             2423, 2437, 2441, 2447, 2459, 2467, 2473, 2477, 2503, 2521,
             2531, 2539, 2543, 2549, 2551, 2557, 2579, 2591, 2593, 2609,
             2617, 2621, 2633, 2647, 2657, 2659, 2663, 2671, 2677, 2683,
             2687, 2689, 2693, 2699, 2707, 2711, 2713, 2719, 2729, 2731
             ]


def isPrime(num: int) -> bool:
    if num == 1:
        return False
    if num == 2:
        return True
    for k in range(2, num // 2 + 1):
        if np.gcd(k, num) != 1:
            return False
    return True


receiver = Receiver()
transmitter = Transmitter()
isImage = False
showImage = False
printImage = 0


print(f"{HEADER}Welcome to Dodgy Dave's Dubious Digital Deception.{ENDC}\nLet's get started!\n\n")
print("To initialise a secure transmission channel, comply with the following instructions:")
print("Please note the following:"
      "\n- The values you enter for p and q must be prime numbers."
      "\n- The values of p and q must multiply to a number greater than 65535."
      "\n- If you don't want to come up with what is asked for, you can simply press enter and we will get our own "
      "default values."
      "\n- When we ask yes or no and you give nothing or invalid input, we assume you meant to say no :)"
      "\n- Have fun.")
print(f"{BOLD}Lets get started!{ENDC}\n\nEnter the following:")

p_input = input(f"{OKBLUE}RECEIVER{ENDC} p value, a good choice is 23:")
q_input = input(f"{OKBLUE}RECEIVER{ENDC} q value, a good choice is 3449:")

if p_input:
    p = int(p_input)
else:
    p = 0

if q_input:
    q = int(q_input)
else:
    q = 0

if (not isPrime(p)) or (not isPrime(q)) or ((p * q) < int(2 ** 16 - 1)) or (p == q):
    print(f"{FAIL}A condition has been violated, setting p and q to random prime numbers.{ENDC}")
    p = int(np.random.choice(smallPrimes))
    q = int(np.random.choice(bigPrimes))

receiver.generate_RSA_Keys(p, q)

print(f"{OKCYAN}\n{line * 3}\n{line}   PHASE 1   {line}\n{line * 3}\n{ENDC}")

print(receiver.printRec())
publicKey = receiver.publicKey

RC4_K = input(f"{OKGREEN}TRANSMITTER{ENDC} Enter the RC4 Key: ")
if not (RC4_K):
    print("Nothing entered, setting key to a random string.")
    RC4_K = ''.join([np.random.choice(list(stringPrintable)) for _ in range(0, 2 * np.random.randint(3, 7))])
if len(RC4_K)<3:
    print(f"{WARNING}Your RC4 Key was not secure, we will replace it with a secure key.")
    RC4_K = ''.join([np.random.choice(list(stringPrintable)) for _ in range(0, 2 * np.random.randint(3, 7))])
if len(RC4_K) % 2 == 1:
    print("To encrypt the key, it must have an even number of bytes, adding a pad to the key.")
    RC4_K = "0" + RC4_K
print(f"RC4 key: {RC4_K}")

RC4_Khex = sha_String_To_Hex(RC4_K)
RC4_K_enc = transmitter.encrypt_With_RSA(RC4_Khex, publicKey)
RC4_K_dec = receiver.decrypt_With_RSA(RC4_K_enc, receiver.privateKey)

transmitter_RC4Key = RC4_K
receiver_RC4Key = sha_Hex_To_Str(RC4_K_dec)

print(f"{OKGREEN}TRANSMITTER{ENDC} RC4 Key in hex: {RC4_Khex}")
print(f"{OKGREEN}TRANSMITTER{ENDC} RC4 Key (encrypted): {RC4_K_enc}")
print(f"{OKBLUE}RECEIVER{ENDC} RC4 Key (decrypted): {RC4_K_dec}")

print(f"{OKCYAN}\n{line * 3}\n{line}   PHASE 2   {line}\n{line * 3}\n{ENDC}")

M = input(f"{OKGREEN}TRANSMITTER{ENDC} Enter a message: ")

if (not M):
    print(f"{FAIL}\nYou should have entered a valid message!\n{ENDC}")
    M = "In cryptography, encryption is the process of encoding " \
        "information. This process converts the original representation of the information, known as plaintext, " \
        "into an alternative form known as ciphertext. Ideally, only authorized parties can decipher a ciphertext " \
        "back to plaintext and access the original information. Encryption does not itself prevent interference but " \
        "denies the intelligible content to a would-be interceptor. For technical reasons, an encryption scheme " \
        "usually uses a pseudo-random encryption key generated by an algorithm. It is possible to decrypt the message " \
        "without possessing the key but, for a well-designed encryption scheme, considerable computational resources " \
        "and skills are required. An authorized recipient can easily decrypt the message with the key provided by the " \
        "originator to recipients but not to unauthorized users. Historically, various forms of encryption have been " \
        "used to aid in cryptography. Early encryption techniques were often used in military messaging. Since then, " \
        "new techniques have emerged and become commonplace in all areas of modern computing.Modern encryption " \
        "schemes use the concepts of public-key and symmetric-key. Modern encryption techniques ensure security " \
        "because modern computers are inefficient at cracking the encryption. This text was taken from wikipedia."

if M[-4:] == ".png":
    isImage = True

    temp = input("Do you want to see the image? Enter 'yes' or 'no': ")
    if not temp:
        temp = 'no'
    showImage = False
    if temp == 'yes':
        showImage = True
    temp = input("Do you want to see the image hex string? Enter 'yes' or 'no': ")
    if not temp:
        temp = 'no'
    printImage = 0
    if temp == 'yes':
        printImage = 1

    img = Image.open(M)
    img = np.array(img)
    if showImage:
        temp = Image.fromarray(img)
        temp.show(title="Plaintext image")
    originalSize = img.shape
    PM_hex = sha_Image_To_Hex(img)
else:
    PM_hex = sha_String_To_Hex(M)

print(f"{OKGREEN}TRANSMITTER: {ENDC}Message/image is \n{M}")
PM_hash = sha_Calculate_Hash(PM_hex)
P_Digest = PM_hex + PM_hash
C_digest = transmitter.encrypt_with_RC4(P_Digest, transmitter_RC4Key)
if showImage:
    # C_image = np.array(C_digest[0:np.prod(originalSize)])
    C_image = np.array(C_digest[0:-64]) # 64 here, last 512 bits is digest = 128 hits = 128 nibble = 64 byte
    C_image = np.reshape(C_image, originalSize)
    C_image = C_image.astype(np.uint8)
    temp = Image.fromarray(C_image)
    temp.show(title="Ciphertext image")

if isImage:
    print(f"{OKGREEN}TRANSMITTER: {ENDC}Plaintext message: \n{PM_hex if printImage==1 else 'Not shown'}")
    print(f"{OKGREEN}TRANSMITTER: {ENDC}Plaintext hash: \n{PM_hash}")
    print(f"{OKGREEN}TRANSMITTER: {ENDC}Plaintext digest: \n{P_Digest  if printImage==1 else 'Not shown'}")
    print(f"{OKGREEN}TRANSMITTER: {ENDC}Ciphertext digest: \n{sha_Image_To_Hex(C_digest) if printImage==1 else 'Not shown'}")
else:
    print(f"{OKGREEN}TRANSMITTER: {ENDC}Plaintext message: \n{PM_hex}")
    print(f"{OKGREEN}TRANSMITTER: {ENDC}Plaintext hash: \n{PM_hash}")
    print(f"{OKGREEN}TRANSMITTER: {ENDC}Plaintext digest: \n{P_Digest}")
    print(f"{OKGREEN}TRANSMITTER: {ENDC}Ciphertext digest: \n{sha_Image_To_Hex(C_digest)}")

print(f"{OKCYAN}\n{line * 3}\n{line}   PHASE 3   {line}\n{line * 3}\n{ENDC}")

digest_dec = receiver.decrypt_With_RC4(C_digest, transmitter_RC4Key)

M_dec, H_dec = receiver.split_Digest(digest_dec)

changeBit = np.random.choice([True, False], p=[0.1, 0.9])
if changeBit:
    M_dec_str = sha_Hex_To_Str(M_dec)
    print(f"{WARNING}Transmission error occurred!{ENDC}")
    byteChange = np.random.randint(0, 4)
    bitChange = np.random.randint(0, 8)

    newByte = ord(M_dec_str[byteChange])
    temp = int(2 ** bitChange)

    newByte = chr(newByte ^ temp)
    M_dec = M_dec_str[0:byteChange] + newByte + M_dec_str[byteChange + 1:]

    M_dec = sha_String_To_Hex(M_dec)

H_calculated = sha_Calculate_Hash(M_dec)

print(f"Expected hash:\n{H_dec}")
print(f"Calculated hash:\n{H_calculated}")

if isImage:
    P_dec = sha_Hex_To_Im(M_dec, originalSize)
else:
    P_dec = sha_Hex_To_Str(M_dec)

if H_calculated != H_dec:
    print(f"{FAIL}Message not authenticated. The authorities have been alerted!{ENDC}")
    if isImage:
        print(f"The erroneous image was:\n{sha_Image_To_Hex(P_dec) if printImage==1 else 'Not shown'}")
        if showImage:
            img = np.array(P_dec)
            img = np.reshape(img, originalSize)
            img = img.astype(np.uint8)
            img = Image.fromarray(img, "RGB")
            img.show(title="Erroneous image")
    else:
        print(f"The erroneous message was:\n{P_dec}")
else:
    print(f"{OKGREEN}Message authenticated{ENDC}")
    if isImage:
        print(f"The image sent was:\n{sha_Image_To_Hex(P_dec) if printImage==1 else 'Not shown'}")
        if showImage:
            img = np.array(P_dec)
            img = np.reshape(img, originalSize)
            img = img.astype(np.uint8)
            img = Image.fromarray(img)
            img.show(title="Image Received and authenticated")
    else:
        print(f"The message sent was:\n{P_dec}")
