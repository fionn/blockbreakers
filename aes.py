#!/usr/bin/env python3
"""Advanced Encryption Standard"""

from functools import reduce

from constants import SBOX_EN, RCON, X2, X3, X9, X11, X13, X14
from utilities import fixed_xor, state_to_matrix, matrix_to_state, \
                      transpose, to_bytes

class AES:
    """Advanced Encryption Standard"""

    @staticmethod
    def rot_word(word: bytes, shift: int = 1) -> bytes:
        """Circular shift"""
        assert len(word) == 4, "Input word must be 4 bytes"
        shift %= 4
        return word[shift:] + word[:shift]

    @staticmethod
    def sub_word(word: bytes) -> bytes:
        """Run word through the sbox"""
        assert len(word) == 4, "Input word must be 4 bytes"
        return bytes(SBOX_EN[b] for b in word)

    @staticmethod
    def rcon(i: int) -> list[bytes]:
        """Round constant for GF(2^8)"""
        return [bytes([RCON[i]]), b"\x00", b"\x00", b"\x00"]

    @staticmethod
    def key_expansion(key: bytes) -> list[bytes]:
        """Generate round keys"""
        words = [key[i:i + 4] for i in range(0, 16, 4)]

        for round_number in range(1, 11):
            index = (round_number - 1) * 4
            word = words[index + 3]
            rcon_word = b"".join(AES.rcon(round_number))
            word_prime = (fixed_xor(AES.sub_word(AES.rot_word(word)),
                                    words[index]))
            words.append(fixed_xor(word_prime, rcon_word))
            for current_round_index in range(1, 4):
                words.append(fixed_xor(words[index + current_round_index],
                                       words[-1]))

        return [b"".join(words[4 * i : 4 * (i + 1)]) for i in range(11)]

    @staticmethod
    def print_state(data: bytes) -> None:
        """Print the internal state as a transposed matrix"""
        for i in range(4):
            for j in range(4):
                print(bytes([data[i + 4 * j]]).hex(), end=" ")
            print()

    @staticmethod
    def sub_bytes(data: bytes) -> bytes:
        """SubBytes transformation"""
        assert len(data) == 16
        return bytes(SBOX_EN[b] for b in data)

    @staticmethod
    def sub_bytes_inverse(data: bytes) -> bytes:
        """Invert the sbox"""
        assert len(data) == 16
        return bytes(SBOX_EN.index(b) for b in data)

    @staticmethod
    def shift_rows(data: bytes) -> bytes:
        """ShiftRows transformation"""
        assert len(data) == 16
        matrix_t = transpose(state_to_matrix(data))
        for i in range(4):
            matrix_t[i] = AES.rot_word(matrix_t[i], i)
        return matrix_to_state(transpose(matrix_t))

    @staticmethod
    def shift_rows_inverse(data: bytes) -> bytes:
        """ShiftRows transformation"""
        assert len(data) == 16
        matrix_t = transpose(state_to_matrix(data))
        for i in range(4):
            matrix_t[i] = AES.rot_word(matrix_t[i], -1 * i)
        return matrix_to_state(transpose(matrix_t))

    # pylint: disable=invalid-name
    @staticmethod
    def mix_column(a: bytes) -> bytes:
        """Multiply the vector a by the MixColumn matrix over GF(2^8)"""
        result = [
            reduce(fixed_xor, map(to_bytes, [X2[a[0]], X3[a[1]], a[2], a[3]])),
            reduce(fixed_xor, map(to_bytes, [a[0], X2[a[1]], X3[a[2]], a[3]])),
            reduce(fixed_xor, map(to_bytes, [a[0], a[1], X2[a[2]], X3[a[3]]])),
            reduce(fixed_xor, map(to_bytes, [X3[a[0]], a[1], a[2], X2[a[3]]]))
        ]
        return b"".join(result)

    # pylint: disable=invalid-name
    @staticmethod
    def mix_column_inverse(a: bytes) -> bytes:
        """Multiply the vector a by the inverse MixColumn matrix over GF(2^8)"""
        result = [
            reduce(fixed_xor, map(to_bytes, [X14[a[0]], X11[a[1]], X13[a[2]], X9[a[3]]])),
            reduce(fixed_xor, map(to_bytes, [X9[a[0]], X14[a[1]], X11[a[2]], X13[a[3]]])),
            reduce(fixed_xor, map(to_bytes, [X13[a[0]], X9[a[1]], X14[a[2]], X11[a[3]]])),
            reduce(fixed_xor, map(to_bytes, [X11[a[0]], X13[a[1]], X9[a[2]], X14[a[3]]]))
        ]
        return b"".join(result)

    @staticmethod
    def mix_columns(data: bytes) -> bytes:
        """MixColumns transformation"""
        matrix = state_to_matrix(data)
        matrix_prime = []
        for column in matrix:
            matrix_prime.append(AES.mix_column(column))
        return matrix_to_state(matrix_prime)

    @staticmethod
    def mix_columns_inverse(data: bytes) -> bytes:
        """Inverted MixColumns transformation"""
        matrix = state_to_matrix(data)
        matrix_prime = []
        for column in matrix:
            matrix_prime.append(AES.mix_column_inverse(column))
        return matrix_to_state(matrix_prime)

    @staticmethod
    def add_round_key(key: bytes, data: bytes) -> bytes:
        """Add a given round key to the state"""
        return fixed_xor(key, data)

    @staticmethod
    def encrypt(message: bytes, key: bytes) -> bytes:
        """AES encryption"""
        assert len(message) == len(key) == 16, "AES-128 operates on 16 bytes"

        # Widen the key to generate subkeys
        keys = AES.key_expansion(key)

        # Pre-whitening
        data = fixed_xor(message, keys[0])

        # Standard intermediate rounds
        for i in range(1, 10):
            data = AES.sub_bytes(data)
            data = AES.shift_rows(data)
            data = AES.mix_columns(data)
            data = AES.add_round_key(keys[i], data)

        # Final round
        data = AES.sub_bytes(data)
        data = AES.shift_rows(data)
        data = AES.add_round_key(keys[10], data)

        return data

    @staticmethod
    def decrypt(ciphertext: bytes, key: bytes) -> bytes:
        """AES decryption"""
        assert len(ciphertext) == len(key) == 16, "AES-128 operates on 16 bytes"

        # Widen the key to generate subkeys
        keys = AES.key_expansion(key)

        # Inverse final round
        data = AES.add_round_key(keys[10], ciphertext)
        data = AES.shift_rows_inverse(data)
        data = AES.sub_bytes_inverse(data)


        # Standard intermediate rounds, inverted
        for i in range(9, 0, -1):
            data = AES.add_round_key(keys[i], data)
            data = AES.mix_columns_inverse(data)
            data = AES.shift_rows_inverse(data)
            data = AES.sub_bytes_inverse(data)

        # Undo pre-whitening
        data = fixed_xor(data, keys[0])

        return data

def main() -> None:
    """Entry point"""
    message = b"attack at dawn!!"
    key = b"yellow submarine"
    ciphertext = AES.encrypt(message, key)
    AES.print_state(ciphertext)

if __name__ == "__main__":
    main()
