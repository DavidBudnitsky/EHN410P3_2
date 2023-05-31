import numpy as np
from 12345678_Prac_3_RC4 import *

# pads message
def sha_Preprocess_Message(inputHex: str) -> str:
    raise Exception("Not Implemented.")


def sha_Create_Message_Blocks(inputHex: str) -> np.ndarray:
    raise Exception("Not Implemented.")

def sha_Message_Schedule(inputHex: str) -> np.ndarray:
    raise Exception("Not Implemented.")


def sha_Hash_Round_Function(messageWordHex: str, aHex: str, bHex: str, cHex: str, dHex: str, eHex: str, fHex: str,
                            gHex: str, hHex: str, roundConstantHex: str) -> tuple:
    raise Exception("Not Implemented.")


def sha_F_Function(messageBlock: str, aHex: str, bHex: str, cHex: str, dHex: str, eHex: str, fHex: str, gHex: str,
                   hHex: str) -> tuple:
    raise Exception("Not Implemented.")


def sha_Process_Message_Block(inputHex: str, aHex: str, bHex: str, cHex: str, dHex: str, eHex: str, fHex: str,
                              gHex: str, hHex: str) -> tuple:
    raise Exception("Not Implemented.")


def sha_Calculate_Hash(inputHex: str) -> str:
    raise Exception("Not Implemented.")


def sha_String_To_Hex(inputStr: str) -> str:
    raise Exception("Not Implemented.")


def sha_Image_To_Hex(inputImg: np.ndarray) -> str:
    raise Exception("Not Implemented.")

def sha_Hex_To_Str(inputHex: str) -> str:
    raise Exception("Not Implemented.")


def sha_Hex_To_Im(inputHex: str, originalShape: tuple) -> np.ndarray:
    raise Exception("Not Implemented.")

class Transmitter:
    def __init__(self, ):
        return

    def encrypt_With_RSA(self, message: str, RSA_Key: tuple) -> np.ndarray:
            raise Exception("Not Implemented.")

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

    def generate_RSA_Keys(self, newP: int, newQ: int):
            raise Exception("Not Implemented.")

    def decrypt_With_RSA(self, message: np.ndarray, RSA_Key: tuple) -> str:
            raise Exception("Not Implemented.")

    def decrypt_With_RC4(self, digest: np.ndarray, key: str) -> str:
            raise Exception("Not Implemented.")

    def split_Digest(self, digest: str) -> tuple:
            raise Exception("Not Implemented.")


    def authenticate_Message(self, digest: str) -> tuple:
            raise Exception("Not Implemented.")


