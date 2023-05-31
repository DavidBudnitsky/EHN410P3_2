# David Budnitsky
# 20453508

import numpy as np
from Prac2RC4 import *


# region helperFunctions
def circularRightShift(num, shifts, numBits=64):
    """
    Right circular right-bit shit
    :param numBits:
    :param num:
    :param shifts:
    :return:
    """
    return (num >> shifts) | (num << (numBits - shifts)) & (int(2 ** numBits) - 1)


def circularLeftShift(num, shifts, numBits=64):
    """
    Left circular bit shift
    :param numBits:
    :param num:
    :param shifts:
    :return:
    """
    return (num << shifts) | (num >> (numBits - shifts))


# endregion helperFunctions


# pads message
def sha_Preprocess_Message(inputHex: str) -> str:
    """
    Takes in a hex input and pads it according to the SHA standard
    :param inputHex: Input message as a hex-string, no padding
    :return: The hex-string of the padded input
    """
    messageLen = len(inputHex) * 4
    inputBin = bin(int(inputHex, 16))[2:].zfill(messageLen)

    k = (896 - messageLen - 1) % 1024

    padding = '1' + '0' * k + bin(messageLen)[2:].zfill(128)

    ans = inputBin + padding
    ansLen = len(ans) // 4

    ans = int(ans, 2)
    ans = hex(ans)[2:].zfill(ansLen)
    return ans


def sha_Create_Message_Blocks(inputHex: str) -> np.ndarray:
    """
    Breaks the message into blocks of 1024 bits, 256 hits per block
    :param inputHex: Preprocessed inputHex hex string
    :return: np array of hex strings, each with 256 characters
    """
    ans = np.array([inputHex[k:k + 256] for k in range(0, len(inputHex), 256)])
    return ans


def sha_Message_Schedule(inputHex: str) -> np.ndarray:
    """
    Makes the message schedule for a block from the inputHex.
    The first 16 message schedule pieces use 64-bit (16 hit) pieces of the message block
    :param inputHex: Input hex value to make the 80 message words from. This should always have a length of 1024.
    :return: Array of 80 words
    """
    W = [inputHex[k:k + 16] for k in range(0, len(inputHex), 16)]
    for k in range(16, 80):
        thisW = [W[k - t] for t in (16, 15, 7, 2)]
        temp = int(thisW[0], 16) + int(thisW[2], 16)

        x = int(thisW[1], 16)
        x1 = circularRightShift(x, 1)
        x2 = circularRightShift(x, 8)
        x3 = x >> 7
        temp1 = (x1 ^ x2 ^ x3)

        x = int(thisW[3], 16)
        x1 = circularRightShift(x, 19)
        x2 = circularRightShift(x, 61)
        x3 = x >> 6
        temp2 = (x1 ^ x2 ^ x3)

        temp = temp + temp1 + temp2
        temp = temp % int(2 ** 64)
        temp = hex(temp)[2:].upper().zfill(16)

        W.append(temp)

    W = np.array(W)
    return W


def sha_Hash_Round_Function(messageWordHex: str, aHex: str, bHex: str, cHex: str, dHex: str, eHex: str, fHex: str,
                            gHex: str, hHex: str, roundConstantHex: str) -> tuple:
    """
    Performs the Hash round function for SHA. Thuis is seen in figure 11.11 in the textbook.
    pdf page 361.
    :param messageWordHex: Self-explanatory
    :param aHex: Self-explanatory
    :param bHex: Self-explanatory
    :param cHex: Self-explanatory
    :param dHex: Self-explanatory
    :param eHex: Self-explanatory
    :param fHex: Self-explanatory
    :param gHex: Self-explanatory
    :param hHex: Self-explanatory
    :param roundConstantHex: Self-explanatory
    :return: Tuple of new a-h as hex strings, each of 64 bits, 16 hits
    """
    a = int(aHex, 16)
    b = int(bHex, 16)
    c = int(cHex, 16)
    d = int(dHex, 16)
    e = int(eHex, 16)
    f = int(fHex, 16)
    g = int(gHex, 16)
    h = int(hHex, 16)

    wt = int(messageWordHex, 16)
    kt = int(roundConstantHex, 16)
    ch = (e & f) ^ ((~e) & g)
    maj = (a & b) ^ (a & c) ^ (b & c)
    sigma0 = circularRightShift(a, 28) ^ circularRightShift(a, 34) ^ circularRightShift(a, 39)
    sigma1 = circularRightShift(e, 14) ^ circularRightShift(e, 18) ^ circularRightShift(e, 41)

    T1 = (h + ch + sigma1 + wt + kt) % int(2 ** 64)
    T2 = (sigma0 + maj) % int(2 ** 64)

    hNew = hex(g)[2:].upper().zfill(16)
    gNew = hex(f)[2:].upper().zfill(16)
    fNew = hex(e)[2:].upper().zfill(16)
    eNew = hex(d + T1)[2:].upper().zfill(16)
    dNew = hex(c)[2:].upper().zfill(16)
    cNew = hex(b)[2:].upper().zfill(16)
    bNew = hex(a)[2:].upper().zfill(16)
    aNew = hex(T1 + T2)[2:].upper().zfill(16)

    ans = (aNew, bNew, cNew, dNew, eNew, fNew, gNew, hNew)
    return ans


def sha_F_Function(messageBlock: str, aHex: str, bHex: str, cHex: str, dHex: str, eHex: str, fHex: str, gHex: str,
                   hHex: str) -> tuple:
    """
    Figure 11.10 in the textbook without the final addition.
    :param messageBlock: Block of the message in hex
    :param aHex: current `a` in hex, a 64 bit = 16 hit string
    :param bHex: current `b` in hex, a 64 bit = 16 hit string
    :param cHex: current `c` in hex, a 64 bit = 16 hit string
    :param dHex: current `d` in hex, a 64 bit = 16 hit string
    :param eHex: current `e` in hex, a 64 bit = 16 hit string
    :param fHex: current `f` in hex, a 64 bit = 16 hit string
    :param gHex: current `g` in hex, a 64 bit = 16 hit string
    :param hHex: current `h` in hex, a 64 bit = 16 hit string
    :return: tuple of new a-h values all hex strings, 16 hits
    """

    messageSchedule = sha_Message_Schedule(messageBlock)

    roundConstants = ['428A2F98D728AE22', '7137449123EF65CD', 'B5C0FBCFEC4D3B2F', 'E9B5DBA58189DBBC',
                      '3956C25BF348B538', '59F111F1B605D019', '923F82A4AF194F9B', 'AB1C5ED5DA6D8118',
                      'D807AA98A3030242', '12835B0145706FBE', '243185BE4EE4B28C', '550C7DC3D5FFB4E2',
                      '72BE5D74F27B896F', '80DEB1FE3B1696B1', '9BDC06A725C71235', 'C19BF174CF692694',
                      'E49B69C19EF14AD2', 'EFBE4786384F25E3', '0FC19DC68B8CD5B5', '240CA1CC77AC9C65',
                      '2DE92C6F592B0275', '4A7484AA6EA6E483', '5CB0A9DCBD41FBD4', '76F988DA831153B5',
                      '983E5152EE66DFAB', 'A831C66D2DB43210', 'B00327C898FB213F', 'BF597FC7BEEF0EE4',
                      'C6E00BF33DA88FC2', 'D5A79147930AA725', '06CA6351E003826F', '142929670A0E6E70',
                      '27B70A8546D22FFC', '2E1B21385C26C926', '4D2C6DFC5AC42AED', '53380D139D95B3DF',
                      '650A73548BAF63DE', '766A0ABB3C77B2A8', '81C2C92E47EDAEE6', '92722C851482353B',
                      'A2BFE8A14CF10364', 'A81A664BBC423001', 'C24B8B70D0F89791', 'C76C51A30654BE30',
                      'D192E819D6EF5218', 'D69906245565A910', 'F40E35855771202A', '106AA07032BBD1B8',
                      '19A4C116B8D2D0C8', '1E376C085141AB53', '2748774CDF8EEB99', '34B0BCB5E19B48A8',
                      '391C0CB3C5C95A63', '4ED8AA4AE3418ACB', '5B9CCA4F7763E373', '682E6FF3D6B2B8A3',
                      '748F82EE5DEFB2FC', '78A5636F43172F60', '84C87814A1F0AB72', '8CC702081A6439EC',
                      '90BEFFFA23631E28', 'A4506CEBDE82BDE9', 'BEF9A3F7B2C67915', 'C67178F2E372532B',
                      'CA273ECEEA26619C', 'D186B8C721C0C207', 'EADA7DD6CDE0EB1E', 'F57D4F7FEE6ED178',
                      '06F067AA72176FBA', '0A637DC5A2C898A6', '113F9804BEF90DAE', '1B710B35131C471B',
                      '28DB77F523047D84', '32CAAB7B40C72493', '3C9EBE0A15C9BEBC', '431D67C49C100D4C',
                      '4CC5D4BECB3E42B6', '597F299CFC657E2A', '5FCB6FAB3AD6FAEC', '6C44198C4A475817']

    aNew = aHex
    bNew = bHex
    cNew = cHex
    dNew = dHex
    eNew = eHex
    fNew = fHex
    gNew = gHex
    hNew = hHex

    for k in range(0, 80):
        aNew, bNew, cNew, dNew, eNew, fNew, gNew, hNew = sha_Hash_Round_Function(messageSchedule[k], aNew, bNew, cNew, dNew, eNew, fNew, gNew, hNew, roundConstants[k])

    ans = (aNew, bNew, cNew, dNew, eNew, fNew, gNew, hNew)
    return ans


def sha_Process_Message_Block(inputHex: str, aHex: str, bHex: str, cHex: str, dHex: str, eHex: str, fHex: str,
                              gHex: str, hHex: str) -> tuple:
    f"""
    Performs sha_F_Function() on the input block then adds a-h to the new a-h.
    
    :param inputHex: Message block
    :param aHex: Current value of a
    :param bHex: Current value of b
    :param cHex: Current value of c
    :param dHex: Current value of d
    :param eHex: Current value of e
    :param fHex: Current value of f
    :param gHex: Current value of g
    :param hHex: Current value of h
    :return: New a-h values
    """

    aNew, bNew, cNew, dNew, eNew, fNew, gNew, hNew = sha_F_Function(inputHex,
                                                                    aHex,
                                                                    bHex,
                                                                    cHex,
                                                                    dHex,
                                                                    eHex,
                                                                    fHex,
                                                                    gHex,
                                                                    hHex)

    aNew = hex(int(aNew, 16) + int(aHex, 16))[2:].upper().zfill(16)
    bNew = hex(int(bNew, 16) + int(bHex, 16))[2:].upper().zfill(16)
    cNew = hex(int(cNew, 16) + int(cHex, 16))[2:].upper().zfill(16)
    dNew = hex(int(dNew, 16) + int(dHex, 16))[2:].upper().zfill(16)
    eNew = hex(int(eNew, 16) + int(eHex, 16))[2:].upper().zfill(16)
    fNew = hex(int(fNew, 16) + int(fHex, 16))[2:].upper().zfill(16)
    gNew = hex(int(gNew, 16) + int(gHex, 16))[2:].upper().zfill(16)
    hNew = hex(int(hNew, 16) + int(hHex, 16))[2:].upper().zfill(16)

    ans = (aNew, bNew, cNew, dNew, eNew, fNew, gNew, hNew)
    return ans


def sha_Calculate_Hash(inputHex: str) -> str:
    raise Exception("Not Implemented.")


def sha_String_To_Hex(inputStr: str) -> str:
    ans = ""
    for char in inputStr:
        temp = hex(ord(char))[2:].upper().zfill(2)
        ans = ans + temp
    return ans


def sha_Image_To_Hex(inputImg: np.ndarray) -> str:
    raise Exception("Not Implemented.")


def sha_Hex_To_Str(inputHex: str) -> str:
    inputBlocks = [inputHex[k:k + 2] for k in range(0, len(inputHex), 2)]
    ans = ""
    for k in inputBlocks:
        k = chr(int(k, 16))
        ans += k
    return ans


def sha_Hex_To_Im(inputHex: str, originalShape: tuple) -> np.ndarray:
    raise Exception("Not Implemented.")


class Transmitter:
    def __init__(self, ):
        return

    def encrypt_With_RSA(self, message: str, RSA_Key: tuple) -> np.ndarray:
        """
        Receives a string of hex characters and encrypts with RSA, 2 bytes at a time. Block sze is 2 bytes, 4 hex characters.

        :param message: Hex string to encrypt. No padding, message will be a multiple of 4 hex chars.
        :param RSA_Key: RSA public key, (e, n)
        :return: 1D int array with encrypted message blocks.
        """
        m_blocks = [int(message[k:k + 4], 16) for k in range(0, len(message), 4)]
        e, n = RSA_Key
        C = [int(i ** e) % n for i in m_blocks]

        C = np.array(C)
        C = C.round(0).astype(int)
        return C

    def create_Digest(self, message) -> str:
        raise Exception("Not Implemented.")

    def encrypt_with_RC4(self, digest: str, key: str) -> np.ndarray:
        raise Exception("Not Implemented.")


class Receiver:
    def __init__(self, ):
        self.p = 0
        self.q = 0
        self.n = 0
        self.phi = 0
        self.e = 0
        self.d = 0
        self.publicKey = (0, 0)
        self.privateKey = (0, 0)

    def printRec(self):
        ans = f"p value: {self.p}\n" \
              + f"q value: {self.q}\n" \
              + f"n value: {self.n}\n" \
              + f"phi value: {self.phi}\n" \
              + f"e value: {self.e}\n" \
              + f"d value: {self.d}\n" \
              + f"PU value: {self.publicKey}\n" \
              + f"PR value: {self.privateKey}\n"
        print(ans)

    def generate_RSA_Keys(self, newP: int, newQ: int):
        """
        Given the p and q values, find:
            p
            q
            n
            phi
            e
            d
            publicKey
            privateKey

        :param newP: new vbalue to go to p
        :param newQ: new value to go to q
        :return: nothing
        """
        n = newP * newQ
        phi = ((newP - 1) * (newQ - 1))

        if phi > (2 ** 16 - 1):
            e = 2 ** 16 - 1
        else:
            e = phi // 4 - 1

        while np.gcd(e, phi) != 1 and e < phi:
            e += 1

        if e >= phi:
            e = phi // 2 + 1
        while np.gcd(e, phi) != 1:
            e += 1

        d = pow(e, -1, phi)

        PU = (e, n)
        PR = (d, n)

        self.p = newP
        self.q = newQ
        self.n = n
        self.phi = phi
        self.e = e
        self.d = d
        self.publicKey = PU
        self.privateKey = PR

    def decrypt_With_RSA(self, message: np.ndarray, RSA_Key: tuple) -> str:
        """
        Will receive an array of ints that make up the ciphertext of the RC4 key.
        Will apply decryption to this key.
        P = C^d mod n
        Encryption is done 2 bytes at a time, so I assume that the same holds for decryption, hence the .zfill(4)
        :param message: Int array of values to decrypt
        :param RSA_Key: Private key for decryption
        :return: Hex string version of P
        """
        P = ""
        d, n = RSA_Key
        for block in message:
            p = int(int(block) ** d) % n
            p = hex(p)[2:].upper().zfill(4)
            P = P + p
        return P

    def decrypt_With_RC4(self, digest: np.ndarray, key: str) -> str:
        raise Exception("Not Implemented.")

    def split_Digest(self, digest: str) -> tuple:
        raise Exception("Not Implemented.")

    def authenticate_Message(self, digest: str) -> tuple:
        raise Exception("Not Implemented.")
