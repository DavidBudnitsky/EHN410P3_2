# David Budnitsky
# 20453508

import numpy as np


# region RC4
def rc4_Init_S_T(key: str) -> np.ndarray:
    """
    Generates initial S and T arrays. Returns a 2D array holding S and T in elements 0 and 1 respectively
    :param key: The encryption key
    :return: [S, T]
    """
    S = [i for i in range(0, 256)]

    K = [ord(k) for k in list(key)]

    T = np.array([])
    while len(T) < 256:
        T = np.concatenate((T, K))

    T = T[0:256]

    S = np.array(S).round(0).astype(int)
    T = np.array(T).round(0).astype(int)

    ans = np.array([S, T]).round(0).astype(int)
    return ans


def rc4_Init_Permute_S(sArray: np.ndarray, tArray: np.ndarray) -> np.ndarray:
    """
    Performs initial permutation on the S array
    :param sArray: S array
    :param tArray: T array
    :return: The permuted S array
    """

    j = 0
    for i in range(0, 256):
        j = (j + sArray[i] + tArray[i]) % 256
        temp = sArray[i]
        sArray[i] = sArray[j]
        sArray[j] = temp

    # sArray = np.array(sArray).round(0).astype(int)
    return np.asarray(sArray)


# returns (i, j, sArray, k)
def rc4_Generate_Stream_Iteration(i: int, j: int, sArray: np.ndarray) -> tuple:
    """
    Generates a random byte stream byte
    :param i: Value used in stream generation
    :param j: Value used in stream generation
    :param sArray: last Modified S array
    :return: tuple containing (i,j,sArray, k)
    """
    i = (i + 1) % 256
    j = (j + sArray[i]) % 256
    temp = sArray[i]
    sArray[i] = sArray[j]
    sArray[j] = temp

    t = (sArray[i] + sArray[j]) % 256
    k = sArray[t]

    return tuple((i, j, sArray, k))


def rc4_Process_Byte(byteToProcess: int, k: int) -> int:
    """
    :param byteToProcess: byte to be processed
    :param k: k value
    :return: biwise XOR of k and byteToProcess
    """
    return np.bitwise_xor(byteToProcess, k)


def rc4_Encrypt_String(plaintext: str, key: str) -> np.ndarray:
    """
    Example usage:
    P = "hello world"
    Phex = sha_String_To_Hex(P)
    C = rc4.rc4_Encrypt_String(Phex, "qwerty")
    Pdec = rc4.rc4_Decrypt_String(C, "qwerty")
    Pstr = sha_Hex_To_Str(Pdec)
    print(Pstr)
    :param plaintext: The plaintext to encrypt. Input is a hex string and encryption will be done byte by byte.
    :param key: The key to initalise S and T with
    :return: Encrypted text as an int np.ndarray
    """
    if len(plaintext) % 2 == 1:
        plaintext = '0' + plaintext

    P = [int(plaintext[i:i + 2], 16) for i in range(0, len(plaintext), 2)]

    S, T = rc4_Init_S_T(key)
    S = rc4_Init_Permute_S(S, T)

    C = []
    i = 0
    j = 0
    for byte in P:
        (i, j, S, k) = rc4_Generate_Stream_Iteration(i, j, S)
        c = rc4_Process_Byte(byte, k)
        C.append(c)
    C = np.array(C).round(0).astype(int)
    return C


def rc4_Decrypt_String(ciphertext: np.ndarray, key: str) -> str:
    """
    Decrypts ciphertext using key provided.

    Example usage:
    P = "hello world"
    Phex = sha_String_To_Hex(P)
    C = rc4.rc4_Encrypt_String(Phex, "qwerty")
    Pdec = rc4.rc4_Decrypt_String(C, "qwerty")
    Pstr = sha_Hex_To_Str(Pdec)
    print(Pstr)

    :param ciphertext: Ciphertext to be decrypted, int np array
    :param key: Key to decrypt with
    :return: Hex-string plaintext.
    """
    S, T = rc4_Init_S_T(key)
    S = rc4_Init_Permute_S(S, T)

    i = 0
    j = 0
    P = ""
    for byte in ciphertext:
        (i, j, S, k) = rc4_Generate_Stream_Iteration(i, j, S)
        p = hex(rc4_Process_Byte(byte, k))[2:].upper().zfill(2)
        P = P + p
    return P


def rc4_Encrypt_Image(plaintext: np.ndarray, key: str) -> np.ndarray:
    """
    :param plaintext: 3D image array to encrypt
    :param key: Key to encrypt with
    :return: 1D array of ciphertext image
    """
    P = plaintext.flatten()
    S, T = rc4_Init_S_T(key)
    S = rc4_Init_Permute_S(S, T)

    C = []
    i = 0
    j = 0
    for char in P:
        (i, j, S, k) = rc4_Generate_Stream_Iteration(i, j, S)
        c = rc4_Process_Byte(char, k)
        C.append(c)
    C = np.array(C).round(0).astype(int)
    return C


def rc4_Decrypt_Image(ciphertext: np.ndarray, key: str) -> np.ndarray:
    """
    :param ciphertext: Ciphertext to decrypt as a 1D int array
    :param key: Key to use for decryption
    :return:
    """
    S, T = rc4_Init_S_T(key)
    S = rc4_Init_Permute_S(S, T)

    P = []
    i = 0
    j = 0
    for char in ciphertext:
        (i, j, S, k) = rc4_Generate_Stream_Iteration(i, j, S)
        c = rc4_Process_Byte(char, k)
        P.append(c)
    P = np.array(P).round(0).astype(int)
    return P

# endregion RC4
