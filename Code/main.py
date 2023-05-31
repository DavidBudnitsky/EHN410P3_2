import numpy as np
import string
import random
import datetime
import Prac2RC4 as pracCode
from PLAINTEXTS import PlainTexts
import os
# For the next line, I had to say `pip install Pillow` in terminal to get it to accept this import
from PIL import Image
import multiprocessing
from u20453508_Prac_3_Backend import *

# Other variables and setups
np.random.seed(0)
random.seed(0)
# stringPrintable = string.printable[0:94]

saveTime = False
stringPrintable = string.printable[0:94]
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
            if saveTime:
                t = str(datetime.datetime.now())
                file.write(t + '\n')
            file.write(textToSave)

    return wrapper


def saveArrayAsImage(arrToSave: np.ndarray, desiredSize: tuple, fName: string):
    """
    Takes in a 1D array, makes it an image and then saves it.
    My convertToImage simply removes the last few things
    :param arrToSave: 1D np.array
    :param desiredSize: tuple of the size of the image to save
    :param fName: Name to save the file under
    :return: None
    """
    img = pracCode.aes_des_rc4_Convert_To_Image(arrToSave, desiredSize)
    img = Image.fromarray(img)
    img.save(fName)


# region RC4 Test Functions
@infoSaver
def RC4STGen():
    K = "hello world"
    ans = pracCode.rc4_Init_S_T(K)
    return np.array2string(ans, separator=',')


# endregion RC4 Test Functions


# RC4 Batch Function calls for strings and images
def RC4StringTests(numKeys: int = 100):
    keys = ''
    ciphers = ''
    for k in range(0, numKeys):
        # Generate a random string of printable characters
        print(f"{RC4_color}RC4 String: Testing key number {k + 1} of {numKeys}")
        K = ''.join(random.choice(stringPrintable) for _ in range(32))
        keys = keys + K + '\n'
        for P in PlainTexts:
            C = pracCode.rc4_Encrypt_String(P, K)

            c = str(C)
            ciphers = ciphers + c + '\n'

            Pd = pracCode.rc4_Decrypt_String(C, K)
            if P != Pd:
                print("Error in RC4 String:")
                print("Plaintext = ", P)
                print("Key = \n", K)
                print("Deciphered Plaintext = ", Pd)
    with open("RC4/StringKeys.txt", "w") as file:
        file.write(keys)
    with open("RC4/StringCiphers.txt", "w") as file:
        file.write(ciphers)


def RC4TestImages(numKeys: int = 1, numImages: int = 1):
    keys = ''
    if numKeys is None:
        numKeys = 1
    if numKeys <= 0:
        numKeys = 1
    directory = "Images/Original/"
    files = os.listdir(directory)
    if numImages == 0:
        numImages = len(files)
    for i, file in enumerate(files[0:numImages]):
        print(f"{RC4_color}RC4 String: Testing file {i + 1} of {numImages}, with filename {file}:")
        imgDir = directory + file
        P = Image.open(imgDir)
        P = np.array(P)
        originalShape = np.shape(P)
        for keyNum in range(0, numKeys):
            print(f"{RC4_color}RC4: Testing {file} with key {keyNum + 1}")
            K = ''.join(random.choice(stringPrintable) for _ in range(32))
            keys = keys + K + '\n'
            C = pracCode.rc4_Encrypt_Image(P, K)

            temp = C.copy()
            fileName = "Images/Encrypted/RC4/key" + str(keyNum) + "_" + file
            saveArrayAsImage(temp, originalShape, fileName)

            Pd = pracCode.rc4_Decrypt_Image(C, K)
            fileName = "Images/Decrypted/RC4/key" + str(keyNum) + "_" + file
            saveArrayAsImage(Pd, originalShape, fileName)
    with open("RC4/ImageKeys.txt", "w") as file:
        file.write(keys)

def testP2_RC4():
    numStringKeys = 10
    numImageKeys = 10
    if __name__ == '__main__':
        processes = [multiprocessing.Process(target=RC4TestImages, args=(numImageKeys, 0)),
                     multiprocessing.Process(target=RC4StringTests, args=(numStringKeys,))]

        for process in processes:
            process.start()
        for process in processes:
            process.join()


def testRSA():
    receiver = Receiver()
    transmitter = Transmitter()
    P1 = "1234567890AB"
    P1 = "0012003400560078009000AB"
    receiver.generate_RSA_Keys(13, 17)
    receiver.printRec()
    PU = receiver.publicKey
    PR = receiver.privateKey
    C = transmitter.encrypt_With_RSA(P1, PU)
    P2 = receiver.decrypt_With_RSA(C, PR)
    print(P2)

def testSHA_preHashing(message: str = "abc"):
    print(message)
    message_hex = sha_String_To_Hex(message)
    temp = sha_Preprocess_Message(message_hex)
    print(f"Preprocessed message: \n {temp}\n with length {len(temp)}")
    temp = sha_Create_Message_Blocks(temp)
    print(f"Message blocks: \n{temp}")

    # print(sha_Hex_To_Str(message_hex))
    # hash = sha_Calculate_Hash(message_hex)
    # hash = 'hashWrong'
    # digest = message_hex + hash
    # recM, recH = Receiver.split_Digest(digest)

# testRSA()
testSHA_preHashing()
testSHA_preHashing('a'*259)
