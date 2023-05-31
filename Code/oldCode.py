import numpy as np
from u20453508_Prac3_RC4 import *


def dec2hex(num: int, width: int = 2):
    """
    Converts a decimal number to a hex equivalent string.
    :param num: Number ton
    :param width:
    :return:
    """
    num = num % int(16 ** width)
    ans = np.base_repr(num, 16)
    while len(ans) < width:
        ans = '0' + ans
    return ans


# pads message
def sha_Preprocess_Message(inputHex: str) -> str:
    """
    Pads input data to be a multiple of 1024 bits, 256 hex characters.
    For the SHA 512 algorithm, the following was needed:
        - last 128 bits are to represent the length of the original text
        - padding is '1' followed by several 0s
    :param inputHex: Data to be padded
    :return: Padded hex string
    """
    inputBin = np.binary_repr(int(inputHex, 16), width=4 * len(inputHex))
    originalLength = len(inputBin)

    desiredMultiple = len(inputBin) // 1024 + 1
    desiredLength = 1024 * desiredMultiple - 128

    firstPadding = '1' + '0' * (desiredLength - originalLength - 1)

    secondPadding = np.binary_repr(originalLength, width=128)

    ansBin = inputBin + firstPadding + secondPadding
    ans = ''
    for k in range(0, len(ansBin), 4):
        temp = ansBin[k:k + 4]
        temp = np.base_repr(int(temp, 2), 16)
        ans += temp

    return ans


def sha_Create_Message_Blocks(inputHex: str) -> np.ndarray:
    """
    Breaks input hex into blocks of 1024 bits, 256 hex characters
    :param inputHex:
    :return:
    """
    blocks = np.array([inputHex[i:i + 256] for i in range(0, len(inputHex), 256)])
    blocks[-1] = blocks[-1].zfill(256)
    return blocks


def sha_Message_Schedule(inputHex: str) -> np.ndarray:
    """
    Generates the message schedule W to be used based on the input value. The textbook shows it as W
    :param inputHex:
    :return:
    """
    W = [inputHex[k:k + 16] for k in range(0, len(inputHex), 16)]
    modNum = 0xFFFFFFFFFFFFFFFF
    for k in range(16, 80):
        thisW = [W[k - t] for t in (16, 15, 7, 2)]
        temp = int(thisW[0], 16) + int(thisW[2], 16)

        # temp1
        arr = np.array(list(np.binary_repr(int(thisW[1], 16), width=64)))
        t1 = np.roll(arr, 1)
        t1 = ''.join(t1)
        t1 = int(t1, 2)

        t2 = np.roll(arr, 8)
        t2 = ''.join(t2)
        t2 = int(t2, 2)

        t3 = int(thisW[1], 16)
        t3 = t3 >> 7

        temp1 = (t1 ^ t2 ^ t3)

        # temp2
        arr = np.array(list(np.binary_repr(int(thisW[3], 16), width=64)))
        t1 = np.roll(arr, 19)
        t1 = ''.join(t1)
        t1 = int(t1, 2)

        t2 = np.roll(arr, 61)
        t2 = ''.join(t2)
        t2 = int(t2, 2)

        t3 = int(thisW[3], 16)
        t3 = t3 >> 6

        temp2 = (t1 ^ t2 ^ t3)

        temp = temp + temp1 + temp2
        temp = temp & modNum
        temp = np.base_repr(temp, 16)

        while len(temp) < 16:
            temp = '0' + temp

        W.append(temp)

    W = np.array(W)
    return W


def sha_Hash_Round_Function(messageWordHex: str, aHex: str, bHex: str, cHex: str, dHex: str, eHex: str, fHex: str,
                            gHex: str, hHex: str, roundConstantHex: str) -> tuple:
    """
    Applies the SHA round function, F to the messageWord.
    :param messageWordHex: Message work the F function is applied to
    :param aHex: a-h respective input to the round function. These are cascaded through.
    :param bHex: a-h respective input to the round function. These are cascaded through.
    :param cHex: a-h respective input to the round function. These are cascaded through.
    :param dHex: a-h respective input to the round function. These are cascaded through.
    :param eHex: a-h respective input to the round function. These are cascaded through.
    :param fHex: a-h respective input to the round function. These are cascaded through.
    :param gHex: a-h respective input to the round function. These are cascaded through.
    :param hHex: a-h respective input to the round function. These are cascaded through.
    :param roundConstantHex: Round constant for the round
    :return: Tuple of new a-h Values, each of which is a hex string
    """
    # General
    Wt = int(messageWordHex, 16)
    Kt = int(roundConstantHex, 16)
    modNum = 0xFFFFFFFFFFFFFFFF  # bitwise and with this number instead of add % 2**64

    a = int(aHex, 16)
    b = int(bHex, 16)
    c = int(cHex, 16)
    d = int(dHex, 16)
    e = int(eHex, 16)
    f = int(fHex, 16)
    g = int(gHex, 16)
    h = int(hHex, 16)

    # Will need a and e as binary arrays
    a_array = np.array(list(np.binary_repr(a, width=64)))
    e_array = np.array(list(np.binary_repr(e, width=64)))

    # For T1
    Ch = (e & f) ^ ((~e) & g)
    # # Get Sigma 1
    e1 = np.roll(e_array, 14)
    e1 = ''.join(e1)
    e1 = int(e1, 2)
    e2 = np.roll(e_array, 18)
    e2 = ''.join(e2)
    e2 = int(e2, 2)
    e3 = np.roll(e_array, 41)
    e3 = ''.join(e3)
    e3 = int(e3, 2)
    sigma1 = (e1 ^ e2 ^ e3)
    # T1
    T1 = (h + Ch + sigma1 + Wt + Kt) & modNum

    # for T2
    Maj = (a & b) ^ (a & c) ^ (b & c)
    # # for sigma0
    a1 = np.roll(a_array, 28)
    a1 = ''.join(a1)
    a1 = int(a1, 2)
    a2 = np.roll(a_array, 34)
    a2 = ''.join(a2)
    a2 = int(a2, 2)
    a3 = np.roll(a_array, 39)
    a3 = ''.join(a3)
    a3 = int(a3, 2)
    sigma0 = (a1 ^ a2 ^ a3)
    # T2
    T2 = (Maj + sigma0) & modNum

    aAns = (T1 + T2) & modNum
    aAns = np.base_repr(aAns, 16)
    while len(aAns) < 16:
        aAns = '0' + aAns

    eAns = (d + T1) & modNum
    eAns = np.base_repr(eAns, 16)
    while len(eAns) < 16:
        eAns = '0' + eAns

    ans = (aAns, aHex, bHex, cHex, eAns, eHex, fHex, gHex)
    return ans


def sha_F_Function(messageBlock: str, aHex: str, bHex: str, cHex: str, dHex: str, eHex: str, fHex: str, gHex: str,
                   hHex: str) -> tuple:
    W = sha_Message_Schedule(messageBlock)

    # Get the round constants as well
    roundConstants = [
        '428a2f98d728ae22', '7137449123ef65cd', 'b5c0fbcfec4d3b2f', 'e9b5dba58189dbbc',
        '3956c25bf348b538', '59f111f1b605d019', '923f82a4af194f9b', 'ab1c5ed5da6d8118',
        'd807aa98a3030242', '12835b0145706fbe', '243185be4ee4b28c', '550c7dc3d5ffb4e2',
        '72be5d74f27b896f', '80deb1fe3b1696b1', '9bdc06a725c71235', 'c19bf174cf692694',
        'e49b69c19ef14ad2', 'efbe4786384f25e3', '0fc19dc68b8cd5b5', '240ca1cc77ac9c65',
        '2de92c6f592b0275', '4a7484aa6ea6e483', '5cb0a9dcbd41fbd4', '76f988da831153b5',
        '983e5152ee66dfab', 'a831c66d2db43210', 'b00327c898fb213f', 'bf597fc7beef0ee4',
        'c6e00bf33da88fc2', 'd5a79147930aa725', '06ca6351e003826f', '142929670a0e6e70',
        '27b70a8546d22ffc', '2e1b21385c26c926', '4d2c6dfc5ac42aed', '53380d139d95b3df',
        '650a73548baf63de', '766a0abb3c77b2a8', '81c2c92e47edaee6', '92722c851482353b',
        'a2bfe8a14cf10364', 'a81a664bbc423001', 'c24b8b70d0f89791', 'c76c51a30654be30',
        'd192e819d6ef5218', 'd69906245565a910', 'f40e35855771202a', '106aa07032bbd1b8',
        '19a4c116b8d2d0c8', '1e376c085141ab53', '2748774cdf8eeb99', '34b0bcb5e19b48a8',
        '391c0cb3c5c95a63', '4ed8aa4ae3418acb', '5b9cca4f7763e373', '682e6ff3d6b2b8a3',
        '748f82ee5defb2fc', '78a5636f43172f60', '84c87814a1f0ab72', '8cc702081a6439ec',
        '90befffa23631e28', 'a4506cebde82bde9', 'bef9a3f7b2c67915', 'c67178f2e372532b',
        'ca273eceea26619c', 'd186b8c721c0c207', 'eada7dd6cde0eb1e', 'f57d4f7fee6ed178',
        '06f067aa72176fba', '0a637dc5a2c898a6', '113f9804bef90dae', '1b710b35131c471b',
        '28db77f523047d84', '32caab7b40c72493', '3c9ebe0a15c9bebc', '431d67c49c100d4c',
        '4cc5d4becb3e42b6', '597f299cfc657e2a', '5fcb6fab3ad6faec', '6c44198c4a475817']
    for k in range(0, 80):
        aHex, bHex, cHex, dHex, eHex, fHex, gHex, hHex = sha_Hash_Round_Function(W[k],
                                                                                 aHex,
                                                                                 bHex,
                                                                                 cHex,
                                                                                 dHex,
                                                                                 eHex,
                                                                                 fHex,
                                                                                 gHex,
                                                                                 hHex,
                                                                                 roundConstants[k])

    newStuff = [aHex, bHex, cHex, dHex, eHex, fHex, gHex, hHex]

    ans = tuple(newStuff)
    return ans


def sha_Process_Message_Block(inputHex: str, aHex: str, bHex: str, cHex: str, dHex: str, eHex: str, fHex: str,
                              gHex: str, hHex: str) -> tuple:
    """
    This function receives a message block, performs the F function on it, and then adds it with H_{i-1}

    :param inputHex: Message block to be hashed
    :param aHex: 64-bit parts of the hash
    :param bHex: 64-bit parts of the hash
    :param cHex: 64-bit parts of the hash
    :param dHex: 64-bit parts of the hash
    :param eHex: 64-bit parts of the hash
    :param fHex: 64-bit parts of the hash
    :param gHex: 64-bit parts of the hash
    :param hHex: 64-bit parts of the hash
    :return: the new a-h
    """
    oldH = np.array([aHex, bHex, cHex, dHex, eHex, fHex, gHex, hHex])

    newH = sha_F_Function(inputHex, aHex, bHex, cHex, dHex, eHex, fHex, gHex, hHex)
    ans1 = [hex((int(oldH[i], 16) + int(newH[i], 16)) % int(2 ** 64))[2:].upper().zfill(16) for i in range(0, 8)]

    ans = tuple(ans1)
    return ans


def sha_Calculate_Hash(inputHex: str) -> str:
    # Initialization
    a = "6A09E667F3BCC908"
    b = "BB67AE8584CAA73B"
    c = "3C6EF372FE94F82B"
    d = "A54FF53A5F1D36F1"
    e = "510E527FADE682D1"
    f = "9B05688C2B3E6C1F"
    g = "1F83D9ABFB41BD6B"
    h = "5BE0CD19137E2179"

    inputHex = sha_Preprocess_Message(inputHex)
    messageBlocks = sha_Create_Message_Blocks(inputHex)

    for messageBlock in messageBlocks:
        a, b, c, d, e, f, g, h = sha_Process_Message_Block(messageBlock, a, b, c, d, e, f, g, h)

    ans = a + b + c + d + e + f + g + h
    return ans


def sha_String_To_Hex(inputStr: str) -> str:
    """
    Converts the input string (printable characters) into hex values. The output of this function is not padded
    :param inputStr: String to convert
    :return: Hex string
    """
    ans = ''
    for c in inputStr:
        temp = dec2hex(ord(c), width=2)
        ans = ans + temp

    return ans


def sha_Image_To_Hex(inputImg: np.ndarray) -> str:
    """
    Receives a 3D array as input. The function flattens the array and converts each element into a hex string.
    :param inputImg:
    :return:
    """
    ans = ''
    inputImg = inputImg.flatten()
    for e in inputImg:
        ans += (dec2hex(e, width=2))
    return ans


def sha_Hex_To_Str(inputHex: str) -> str:
    ans = ''
    for k in range(0, len(inputHex), 2):
        temp = inputHex[k] + inputHex[k + 1]
        temp = chr(int(temp, 16))
        ans += temp
    return ans


def sha_Hex_To_Im(inputHex: str, originalShape: tuple) -> np.ndarray:
    ans = np.ones(len(inputHex))
    for i, k in enumerate(inputHex):
        ans[i] = int(inputHex[k], 16)
    # Ensure that ans is of the correct length
    ans = np.reshape(ans, originalShape)
    return ans


class Transmitter:
    def __init__(self, ):
        return

    def encrypt_With_RSA(self, message: str, RSA_Key: tuple) -> np.ndarray:
        e, n = RSA_Key
        ans = []
        for k in range(0, len(message), 4):
            temp = int(message[k:k + 4], 16)
            C = int(temp ** e) % n
            ans.append(C)

        ans = np.array(ans).astype(int).round(0)
        return ans

    def create_Digest(self, message) -> str:
        """
        From the guide:
        Takes in a message and returns the digest. Digest = message || hash
        :param message: String or image array
        :return: Hex string with the hash appended
        """
        test = "pranked you"

        if type(test) == type(message):
            hexStr = sha_String_To_Hex(message)
        else:
            hexStr = sha_Image_To_Hex(message)

        ans = hexStr + sha_Calculate_Hash(hexStr)
        return ans

    def encrypt_with_RC4(self, digest: str, key: str) -> np.ndarray:
        """
        Takes in hex digest and string key. Encrypts with RC4 and returns the array associated with it.
        :param digest: Hex to be encrypted
        :param key: RC4 Key
        :return: Encrypted digest as 1D int array with encrypted data
        """
        return rc4_Encrypt_String(digest, key)


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

    def generate_RSA_Keys(self, newP: int, newQ: int):
        self.p = newP
        self.q = newQ

        self.n = self.p * self.q
        self.phi = (self.p - 1) * (self.q - 1)

        if self.phi <= 17:
            e = 3
        else:
            e = 17

        if self.phi > 65537:
            e = 65537

        while np.gcd(e, self.phi) != 1 and e < self.phi:
            e += 1

        d = pow(e, -1, self.phi)

        self.e = e
        self.d = d

        self.publicKey = (self.e, self.n)
        self.privateKey = (self.d, self.n)

    def decrypt_With_RSA(self, message: np.ndarray, RSA_Key: tuple) -> str:
        """
        Receives encrypted RC4 key, decrypts via RSA
        :param message: Encrypted data
        :param RSA_Key: RSA Key to use for decryption
        :return: RC4 key as hex string
        """
        d, n = RSA_Key
        P = ""
        for C in message:
            p = int(int(C) ** d) % n
            p = np.base_repr(p, 16)
            p = p.zfill(4)

            P = P + p
        return P

    def decrypt_With_RC4(self, digest: np.ndarray, key: str) -> str:
        """

        :param digest:
        :param key:
        :return:
        """
        ans = rc4_Decrypt_String(digest, key)
        return ans
        # raise Exception("Not Implemented.")

    def split_Digest(self, digest: str) -> tuple:
        """
        - Receives the hex string digest and splits it into the message and the hash value
        :param digest: M||H
        :return: Tuple with (M, H)
        """
        # message = digest[0:-128]
        # hash = digest[-128:]
        # ans = (message, hash)

        return tuple([digest[0:-128], digest[-128:]])

    def authenticate_Message(self, digest: str) -> tuple:
        """
        Calculates the hash and verifies message authenticity
        :param digest: M || H
        :return: Tuple of (boolean, M, H, H_calculated)
        """

        M, H = self.split_Digest(digest)
        H_calculated = sha_Calculate_Hash(M)
        b = (H == H_calculated)
        ans = (b, M, H, H_calculated)
        return ans