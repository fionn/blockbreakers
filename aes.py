#!/usr/bin/env python3
"""Advanced Encryption Standard"""

from functools import reduce

from constants import SBOX_EN, RCON, X2, X3, X9, X11, X13, X14
from utilities import fixed_xor, state_to_matrix, matrix_to_state, \
                      transpose, to_bytes


def rot_word(word: bytes, shift: int = 1) -> bytes:
    """Circular shift"""
    assert len(word) == 4, "Input word must be 4 bytes"
    shift %= 4
    return word[shift:] + word[:shift]


def sub_word(word: bytes) -> bytes:
    """Run word through the sbox"""
    assert len(word) == 4, "Input word must be 4 bytes"
    return bytes(SBOX_EN[b] for b in word)


def rcon(i: int) -> list[bytes]:
    """Round constant for GF(2^8)"""
    return [bytes([RCON[i]]), b"\x00", b"\x00", b"\x00"]


def key_expansion(key: bytes, rounds: int = 10) -> list[bytes]:
    """Generate round keys"""
    words = [key[i:i + 4] for i in range(0, 16, 4)]

    for round_number in range(1, rounds + 1):
        index = (round_number - 1) * 4
        word = words[index + 3]
        rcon_word = b"".join(rcon(round_number))
        word_prime = (fixed_xor(sub_word(rot_word(word)),
                                words[index]))
        words.append(fixed_xor(word_prime, rcon_word))
        for current_round_index in range(1, 4):
            words.append(fixed_xor(words[index + current_round_index],
                                   words[-1]))

    return [b"".join(words[4 * i: 4 * (i + 1)]) for i in range(rounds + 1)]


def print_state(state: bytes) -> None:
    """Print the internal state as a transposed matrix"""
    for i in range(4):
        for j in range(4):
            print(bytes([state[i + 4 * j]]).hex(), end=" ")
        print()


def sub_bytes(state: bytes) -> bytes:
    """SubBytes transformation"""
    assert len(state) == 16
    return bytes(SBOX_EN[b] for b in state)


def sub_bytes_inverse(state: bytes) -> bytes:
    """Invert the sbox"""
    assert len(state) == 16
    return bytes(SBOX_EN.index(b) for b in state)


def shift_rows(state: bytes) -> bytes:
    """ShiftRows transformation"""
    assert len(state) == 16
    matrix_t = transpose(state_to_matrix(state))
    for i in range(4):
        matrix_t[i] = rot_word(matrix_t[i], i)
    return matrix_to_state(transpose(matrix_t))


def shift_rows_inverse(state: bytes) -> bytes:
    """ShiftRows transformation"""
    assert len(state) == 16
    matrix_t = transpose(state_to_matrix(state))
    for i in range(4):
        matrix_t[i] = rot_word(matrix_t[i], -1 * i)
    return matrix_to_state(transpose(matrix_t))


def mix_column(a: bytes) -> bytes:
    """Multiply the vector a by the MixColumn matrix over GF(2^8)"""
    result = [
        reduce(fixed_xor, map(to_bytes, [X2[a[0]], X3[a[1]], a[2], a[3]])),
        reduce(fixed_xor, map(to_bytes, [a[0], X2[a[1]], X3[a[2]], a[3]])),
        reduce(fixed_xor, map(to_bytes, [a[0], a[1], X2[a[2]], X3[a[3]]])),
        reduce(fixed_xor, map(to_bytes, [X3[a[0]], a[1], a[2], X2[a[3]]]))
    ]
    return b"".join(result)


def mix_column_inverse(a: bytes) -> bytes:
    """Multiply the vector a by the inverse MixColumn matrix over GF(2^8)"""
    result = [
        reduce(fixed_xor, map(to_bytes, [X14[a[0]], X11[a[1]], X13[a[2]], X9[a[3]]])),
        reduce(fixed_xor, map(to_bytes, [X9[a[0]], X14[a[1]], X11[a[2]], X13[a[3]]])),
        reduce(fixed_xor, map(to_bytes, [X13[a[0]], X9[a[1]], X14[a[2]], X11[a[3]]])),
        reduce(fixed_xor, map(to_bytes, [X11[a[0]], X13[a[1]], X9[a[2]], X14[a[3]]]))
    ]
    return b"".join(result)


def mix_columns(state: bytes) -> bytes:
    """MixColumns transformation"""
    matrix = state_to_matrix(state)
    matrix_prime = []
    for column in matrix:
        matrix_prime.append(mix_column(column))
    return matrix_to_state(matrix_prime)


def mix_columns_inverse(state: bytes) -> bytes:
    """Inverted MixColumns transformation"""
    matrix = state_to_matrix(state)
    matrix_prime = []
    for column in matrix:
        matrix_prime.append(mix_column_inverse(column))
    return matrix_to_state(matrix_prime)


def add_round_key(key: bytes, state: bytes) -> bytes:
    """Add a given round key to the state"""
    return fixed_xor(key, state)


def encrypt(key: bytes, message: bytes, rounds: int = 10) -> bytes:
    """AES Encryption"""
    assert len(message) == len(key) == 16, "128 operates on 16 bytes"

    keys = key_expansion(key, rounds)

    state = fixed_xor(message, keys[0])

    for i in range(1, rounds):
        state = sub_bytes(state)
        state = shift_rows(state)
        state = mix_columns(state)
        state = add_round_key(keys[i], state)

    state = sub_bytes(state)
    state = shift_rows(state)
    state = add_round_key(keys[rounds], state)

    return state


def decrypt(key: bytes, ciphertext: bytes, rounds: int = 10) -> bytes:
    """AES Decryption"""
    assert len(ciphertext) == len(key) == 16, "128 operates on 16 bytes"

    keys = key_expansion(key, rounds)

    state = add_round_key(keys[rounds], ciphertext)
    state = shift_rows_inverse(state)
    state = sub_bytes_inverse(state)

    for i in range(rounds - 1, 0, -1):
        state = add_round_key(keys[i], state)
        state = mix_columns_inverse(state)
        state = shift_rows_inverse(state)
        state = sub_bytes_inverse(state)

    state = fixed_xor(state, keys[0])

    return state


def main() -> None:
    """Entry point"""
    message = b"attack at dawn!!"
    key = b"yellow submarine"
    ciphertext = encrypt(key=key, message=message)
    print_state(ciphertext)


if __name__ == "__main__":
    main()
