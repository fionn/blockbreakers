#!/usr/bin/env python3
"""The SQUARE attack on AES"""

from functools import reduce
from random import randbytes

import aes
import utilities


KEY = b"\xaa" + bytes(15)
ROUNDS = 4


def gen_lambda_set(passive_bytes: bytes) -> list[bytes]:
    """Generate a Λ-set with active bytes at index 0"""
    return [i.to_bytes(1, "big") + passive_bytes for i in range(256)]


def setup(key: bytes, rounds: int) -> list[bytes]:
    """Oracle to produce a variable-round AES-encrypted Λ-set"""
    lambda_set = gen_lambda_set(randbytes(1) * 15)
    return [aes.encrypt(key, m, rounds=rounds) for m in lambda_set]


def reverse_state(key_guess: bytes, index: int,
                  encrypted_lambda_set: list[bytes]) -> list[bytes]:
    """Assuming a key of 00s except at index where it has value key_guess,
       reverse the final round to get the previous state for all states
       in the encrypted Λ-set"""
    assert len(key_guess) == 1

    key_array = bytearray(16)
    key_array[index] = int.from_bytes(key_guess, "big")
    key = bytes(key_array)

    previous_round_lambda_set = []

    for state in encrypted_lambda_set:
        state = aes.add_round_key(key, state)
        # Don't invert shift rows
        state = aes.sub_bytes_inverse(state)
        previous_round_lambda_set.append(state)

    return previous_round_lambda_set


def check_key_guess(reversed_state: list[bytes], index: int) -> bool:
    """For some key with active byte at index, check if the reversed state
       is balanced"""
    index_bytes = [x[index].to_bytes(1, "big") for x in reversed_state]
    integral = reduce(utilities.fixed_xor, index_bytes)
    return integral == b"\x00"


def guess_key_index_byte(index: int,
                         encrypted_lambda_set: list[bytes]) -> set[bytes]:
    """Generate a set of candidate bytes for the key at index"""
    guesses = set()
    for key_int in range(256):
        key_byte = key_int.to_bytes(1, "big")
        reversed_state = reverse_state(key_byte, index, encrypted_lambda_set)
        if check_key_guess(reversed_state, index):
            guesses.add(key_byte)

    return guesses


def reduce_guesses(guessed_key: list[set[bytes]]) -> bytes:
    """Eliminate multiple byte options in the guessed key"""
    key = b""
    for i in range(16):
        guessed_byte_set = guessed_key[i]
        while len(guessed_byte_set) > 1:
            encrypted_lambda_set = setup(KEY, ROUNDS)
            new_guess_set = guess_key_index_byte(i, encrypted_lambda_set)
            guessed_byte_set.intersection_update(new_guess_set)
        key += guessed_byte_set.pop()

    assert len(key) == 16
    return key


def recover_last_round_key() -> bytes:
    """Recover the last round key in mini-AES via the Square attack"""
    encrypted_lambda_set = setup(KEY, ROUNDS)
    guessed_key: list[set[bytes]] = [set() for _ in range(16)]

    for i in range(16):
        guessed_bytes = guess_key_index_byte(i, encrypted_lambda_set)
        guessed_key[i] = guessed_bytes

    return reduce_guesses(guessed_key)


def key_contraction(key: bytes, rounds: int = 10) -> bytes:
    """Given a round key after a specific number of rounds,
       invert aes.key_expansion to recover the original key"""
    # Reverse word order so we index them backwards
    words = [key[i:i + 4] for i in range(0, 16, 4)][::-1]

    # But use the real, non-reversed round number
    for round_number in range(rounds, 0, -1):
        # So calculate the reverse base index instead
        i_0 = (rounds - round_number) * 4

        for i in range(3):
            words.append(utilities.fixed_xor(words[i_0 + i],
                                             words[i_0 + i + 1]))

        w_prime = aes.sub_word(aes.rot_word(words[i_0 + 4]))
        w_prime = utilities.fixed_xor(w_prime, aes.rcon(round_number))
        words.append(utilities.fixed_xor(w_prime, words[i_0 + 3]))

    return b"".join(words[::-1][:4])


def attack() -> bytes:
    """Recover the key in mini-AES via the Square attack"""
    last_round_key = recover_last_round_key()
    return key_contraction(last_round_key, ROUNDS)


def main() -> None:
    """Entry point"""
    key = attack()
    assert key == KEY
    print(bytes.hex(key))


if __name__ == "__main__":
    main()
