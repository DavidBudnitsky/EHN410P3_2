import numpy as np
import string
from PLAINTEXTS import PlainTexts
import os
from PIL import Image
import multiprocessing
import u20453508_Prac_3_RC4 as RC4
from u20453508_Prac_3_Backend import *

# Other variables and setups
np.random.seed(0)
stringPrintable = string.printable[0:94]
hexChars = "0123456789ABCDEF"
keys = [
    "P@ssw0rd! 123",
    "S3cur3 Key$",
    "N0t3b00k #789",
    "Ch3ck M@il*",
    "L0g1n $ucce$$",
    "Fr33 D0wnl0ad$",
    "H@ppy D@ys! 2023",
    "P1nk Fl0wer$",
    "T3ch G3n1u$",
    "C0d3 M@st3r!",
    "Saf3 Tr@v3l$",
    "Sp@rkL3 _ &Sh1n3",
    "M0onL1gh t@786",
    "Blu3 Sk1e$#42",
    "S3cur1ty @F1r$t",
]

AES_color = '\033[96m'
DES_color = '\033[92m'
RC4_color = '\033[95m'


# Saves test outputs to textfiles
def infoSaver(func):
    def wrapper(*args, **kwargs):
        textToSave = func(*args, **kwargs)
        fileName = func.__name__ + '.txt'
        folderName = fileName[0:3]
        fileName = folderName + '/' + fileName
        with open(fileName, 'w') as file:
            file.write(textToSave)

    return wrapper


def testRSA():
    receiver = Receiver()
    transmitter = Transmitter()
    P1 = "1234567890AB"
    P1 = "0012003400560078009000AB"
    P1 = "443421407829"
    receiver.generate_RSA_Keys(23, 3449)
    receiver.printRec()
    PU = receiver.publicKey
    PR = receiver.privateKey
    C = transmitter.encrypt_With_RSA(P1, PU)
    P2 = receiver.decrypt_With_RSA(C, PR)
    print(P2)


def testRC4Strings():
    for P in PlainTexts:
        for k in keys:
            Phex = sha_String_To_Hex(P)
            C = RC4.rc4_Encrypt_String(Phex, k)
            Pdec = RC4.rc4_Decrypt_String(C, k)
            Pdec_str = sha_Hex_To_Str(Pdec)
            if Pdec_str != P:
                print("Error")


# Crashes, IDK why
def testImageHashing():
    """
    Hashes each P in Plaintexts and also P*150.
    M = P || H
    Saves to M.txt and M150.txt
    :return:
    """
    a = 1

# testRC4Strings()
# testImageHashing()
# testRSA()

