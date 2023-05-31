# David Budnitsky
# 20453508

import numpy as np


def aes_des_rc4_Convert_To_Image(arrayToConvert: np.ndarray, originalShape: tuple) -> np.ndarray:
    """
    Transforms image data back into a 3d array as was previously used. Some form of padding will be added.
    Three cases can arise:
    - The array to convert is the perfect length:
        Simply reshape and return. This will correspond to the original shape.
    - The array is too short:
        Pad the array with enough elements (copies of the last element in the array), reshape and return.
        This will correspond to the original shape
    - The array is too long:
        Pad the array with enough elements to fill an extra layer, reshape and return.
        This will not correspond to the original shape, but it is better to add unnecessary data than to omit useful
        data.
    :param arrayToConvert: The 1D array to reshape into a 3D array
    :param originalShape: The shape of the original array
    :return:
    """
    bigLength = 1
    for k in originalShape:
        bigLength *= k
    if len(arrayToConvert) == bigLength:
        # just convert to image and return
        ans = np.reshape(arrayToConvert, originalShape)
        ans = ans.round(0).astype(np.uint8)
        return ans
    if len(arrayToConvert) < bigLength:
        # append the last element in the array, then reshape, then return
        appendage = [arrayToConvert[-1]] * (bigLength - len(arrayToConvert))
        ans = np.append(arrayToConvert, appendage)
        ans = np.reshape(ans, originalShape)
        ans = ans.round(0).astype(np.uint8)
        return ans
    else:
        # the array is too long, remove the last few elements but do not change the
        ans = arrayToConvert[0:bigLength]
        ans = np.reshape(ans, originalShape)
        ans = ans.round(0).astype(np.uint8)
        return ans

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
    :param plaintext: The plaintext to encrypt
    :param key: The key to initalise S and T with
    :return: Encrypted text as an int np.ndarray
    """
    P = [ord(c) for c in plaintext]
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


def rc4_Decrypt_String(ciphertext: np.ndarray, key: str) -> str:
    """
    Decrypts ciphertext using key provided
    :param ciphertext: Ciphertext to be decrypted
    :param key: Key to decrypt with
    :return: String plaintext
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
    ans = [chr(c) for c in P]
    ans = ''.join(ans)
    return ans


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
