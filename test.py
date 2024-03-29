#!/usr/bin/env python3
"""Unit tests"""

import io
import unittest
from functools import reduce
from contextlib import redirect_stdout

import aes
import square
import utilities


class TestUtilities(unittest.TestCase):
    """Tests for helper functions"""

    def test_index_to_coordinate(self) -> None:
        """Test mapping byte indices to coordinates"""
        self.assertEqual(utilities.index_to_coordinate(5), (1, 1))

    def test_coordinate_to_index(self) -> None:
        """Test mapping coordinates to byte indices"""
        self.assertEqual(utilities.coordinate_to_index((2, 3)), 14)

    def test_coordinate_index_inverse(self) -> None:
        """Test that index and coordinate maps are inverses"""
        for i in range(16):
            self.assertEqual(i, utilities.coordinate_to_index(
                utilities.index_to_coordinate(i)
            ))


# pylint: disable=too-many-public-methods
class TestAES(unittest.TestCase):
    """Tests for AES"""

    def test_rot_word(self) -> None:
        """Test circular shift"""
        word = b"\x00\x01\x02\x03"
        self.assertEqual(aes.rot_word(word), b"\x01\x02\x03\x00")

    def test_rot_word_too_long(self) -> None:
        """Test circular shift with 5 bytes"""
        word = b"\x00\x01\x02\x03\x04"
        with self.assertRaises(AssertionError):
            aes.rot_word(word)

    def test_rot_word_too_short(self) -> None:
        """Test circular shift with 3 bytes"""
        word = b"\x00\x01\x02"
        with self.assertRaises(AssertionError):
            aes.rot_word(word)

    def test_sub_word(self) -> None:
        """Test subword against test vectors"""
        word = b"\x01\xc2\x9e\x00"
        self.assertEqual(aes.sub_word(word), b"\x7c\x25\x0b\x63")

    def test_rcon(self) -> None:
        """Test rcon against test vectors"""
        self.assertEqual(aes.rcon(1), b"\x01\x00\x00\x00")
        self.assertEqual(aes.rcon(2), b"\x02\x00\x00\x00")
        self.assertEqual(aes.rcon(3), b"\x04\x00\x00\x00")
        self.assertEqual(aes.rcon(4), b"\x08\x00\x00\x00")

    def test_key_expansion(self) -> None:
        """Test key expansion"""
        test_subkeys = ["2b7e151628aed2a6abf7158809cf4f3c",
                        "a0fafe1788542cb123a339392a6c7605",
                        "f2c295f27a96b9435935807a7359f67f",
                        "3d80477d4716fe3e1e237e446d7a883b",
                        "ef44a541a8525b7fb671253bdb0bad00",
                        "d4d1c6f87c839d87caf2b8bc11f915bc",
                        "6d88a37a110b3efddbf98641ca0093fd",
                        "4e54f70e5f5fc9f384a64fb24ea6dc4f",
                        "ead27321b58dbad2312bf5607f8d292f",
                        "ac7766f319fadc2128d12941575c006e",
                        "d014f9a8c9ee2589e13f0cc8b6630ca6",
                       ]
        subkeys = aes.key_expansion(bytes.fromhex(test_subkeys[0]))
        self.assertEqual([key.hex() for key in subkeys], test_subkeys)

    def test_print_state(self) -> None:
        """Hack test on the state representation"""
        state = bytes(range(16))
        output_buffer = io.StringIO()
        with redirect_stdout(output_buffer):
            aes.print_state(state)
        state_repr = output_buffer.getvalue().strip()
        self.assertEqual(len(state_repr), 50)
        self.assertEqual(state_repr[:11], "00 04 08 0c")
        self.assertEqual(state_repr[-2::], "0f")

    def test_sub_bytes(self) -> None:
        """Test the SubBytes transformation"""
        state = bytes(range(16))
        state_prime = aes.sub_bytes(state)
        self.assertEqual(state_prime,
                         bytes.fromhex("637c777bf26b6fc53001672bfed7ab76"))

    def test_shift_rows(self) -> None:
        """Test the ShiftRows transformation"""
        state = bytes.fromhex("637c777bf26b6fc53001672bfed7ab76")
        state_prime = aes.shift_rows(state)
        self.assertEqual(state_prime,
                         bytes.fromhex("636b6776f201ab7b30d777c5fe7c6f2b"))

    def test_mix_columns(self) -> None:
        """Test the MixColumns transformation"""
        state = bytes.fromhex("636b6776f201ab7b30d777c5fe7c6f2b")
        state_prime = aes.mix_columns(state)
        self.assertEqual(state_prime,
                         bytes.fromhex("6a6a5c452c6d3351b0d95d61279c215c"))

    def test_add_round_key(self) -> None:
        """Test adding the round key"""
        state = bytes.fromhex("6a6a5c452c6d3351b0d95d61279c215c")
        key = bytes.fromhex("d6aa74fdd2af72fadaa678f1d6ab76fe")
        state_prime = aes.add_round_key(key, state)
        self.assertEqual(state_prime,
                         bytes.fromhex("bcc028b8fec241ab6a7f2590f13757a2"))

    def test_round(self) -> None:
        """End to end test for all the round functions"""
        state = bytes(range(16))
        key = bytes.fromhex("d6aa74fdd2af72fadaa678f1d6ab76fe")
        state = aes.sub_bytes(state)
        state = aes.shift_rows(state)
        state = aes.mix_columns(state)
        state = aes.add_round_key(key, state)
        self.assertEqual(state,
                         bytes.fromhex("bcc028b8fec241ab6a7f2590f13757a2"))

    def test_encryption(self) -> None:
        """Test AES encryption"""
        message = b"theblockbreakers"
        key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
        ciphertext = aes.encrypt(key=key, message=message)
        self.assertEqual(ciphertext,
                         bytes.fromhex("c69f25d0025a9ef32393f63e2f05b747"))

    def test_encryption_with_test_vector(self) -> None:
        """Test AES encryption with test vector from appendix C.1"""
        message = bytes.fromhex("00112233445566778899aabbccddeeff")
        key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
        ciphertext = aes.encrypt(key=key, message=message)
        self.assertEqual(ciphertext,
                         bytes.fromhex("69c4e0d86a7b0430d8cdb78070b4c55a"))

    def test_inverse_rot_word(self) -> None:
        """Test inverting word rotation"""
        message = b"0123"
        for i in range(4):
            message_prime = aes.rot_word(message, i)
            self.assertEqual(message, aes.rot_word(message_prime, -1 * i))

    def test_inverse_sub_bytes(self) -> None:
        """Test SubBytes inverse"""
        message = b"0123456789abcdef"
        message_prime = aes.sub_bytes_inverse(message)
        self.assertEqual(message, aes.sub_bytes(message_prime))

    def test_shift_rows_inverse(self) -> None:
        """Test ShiftRows inverse"""
        message = b"0123456789abcdef"
        message_prime = aes.shift_rows_inverse(message)
        self.assertEqual(message, aes.shift_rows(message_prime))

    def test_mix_column_inverse(self) -> None:
        """Test inverting the MixColumn matrix on a single vector"""
        a = b"1000"
        a_prime = aes.mix_column_inverse(a)
        self.assertEqual(a, aes.mix_column(a_prime))

    def test_mix_columns_inverse(self) -> None:
        """Test MixColumns inverse"""
        message = b"0123456789abcdef"
        message_prime = aes.mix_columns_inverse(message)
        self.assertEqual(message, aes.mix_columns(message_prime))

    def test_decryption(self) -> None:
        """Test AES decryption"""
        message = b"theblockbreakers"
        key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
        ciphertext = aes.encrypt(key=key, message=message)
        message_prime = aes.decrypt(key=key, ciphertext=ciphertext)
        self.assertEqual(message, message_prime)

    def test_decryption_with_test_vector(self) -> None:
        """Test AES decryption with test vector from appendix C.1"""
        ciphertext = bytes.fromhex("69c4e0d86a7b0430d8cdb78070b4c55a")
        key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
        message = aes.decrypt(key, ciphertext=ciphertext)
        self.assertEqual(message,
                         bytes.fromhex("00112233445566778899aabbccddeeff"))

    def test_variable_rounds(self) -> None:
        """Test mini-AES with variable number of rounds"""
        message = b"attack at dawn!!"
        key = b"yellow submarine"
        for i in range(14):
            ciphertext = aes.encrypt(key, message, rounds=i)
            self.assertEqual(message, aes.decrypt(key, ciphertext, rounds=i))


class TestSaturationAttack(unittest.TestCase):
    """Test saturation attack on mini-AES"""

    KEY = b"\xaa" + bytes(15)

    def test_lambda_set(self) -> None:
        """Test that Λ-set generation meets specification"""
        lambda_set = square.gen_lambda_set(bytes(15))
        self.assertEqual(len(lambda_set), 256)
        for i in range(256):
            self.assertEqual(lambda_set[i][0], i)
            self.assertEqual(lambda_set[i][1:], bytes(15))

    def test_3_round_balance_property(self) -> None:
        """Test that the balance property holds"""
        encrypted_lambda_set = square.setup(self.KEY, rounds=3)
        for i in range(16):
            slice_i = [x[i].to_bytes(1, "big") for x in encrypted_lambda_set]
            integral = reduce(utilities.fixed_xor, slice_i)
            self.assertEqual(integral, b"\x00")

    def test_reverse_state(self) -> None:
        """Impossible to unit test reversing the state"""
        encrypted_lambda_set = square.setup(self.KEY, rounds=3)
        index = 5
        key_byte = b"\x00"
        reversed_state = square.reverse_state(key_byte, index, encrypted_lambda_set)
        self.assertEqual(len(reversed_state), 256)

    def test_trivial_check_key_guess(self) -> None:
        """Test the balance ckeck with a 3-round encrypted Λ-set"""
        encrypted_lambda_set = square.setup(square.KEY, rounds=3)
        for i in range(16):
            self.assertTrue(square.check_key_guess(encrypted_lambda_set, i))

    def test_reverse_state_validate_guess(self) -> None:
        """Non-trivial test of reversed state key active byte guess"""
        encrypted_lambda_set = square.setup(self.KEY, rounds=3)
        index = 5
        round_keys = aes.key_expansion(square.KEY, rounds=4)
        key_byte = round_keys[-1][index].to_bytes(1, "big")
        reversed_state = square.reverse_state(key_byte, index, encrypted_lambda_set)
        self.assertTrue(square.check_key_guess(reversed_state, index))

    def test_guess_key_index_byte(self) -> None:
        """Guess a byte of the key"""
        encrypted_lambda_set = square.setup(self.KEY, rounds=3)
        index = 5
        round_keys = aes.key_expansion(square.KEY, rounds=4)
        key_byte = round_keys[-1][index].to_bytes(1, "big")
        guesses = square.guess_key_index_byte(index, encrypted_lambda_set)
        self.assertIn(key_byte, guesses)

    def test_reduce_guesses(self) -> None:
        """Given a fake round key with one byte uncertain, recover the key"""
        round_key = aes.key_expansion(square.KEY, square.ROUNDS)[-1]
        guessed_key: list[set[bytes]] = [{x.to_bytes(1, "big")} for x in round_key]
        guessed_key[5].update({b"\x00", b"\xff"})
        key_prime = square.reduce_guesses(guessed_key)
        self.assertEqual(round_key, key_prime)

    @unittest.skip("long test")
    def test_square_recover_last_round_key(self) -> None:
        """Recover the last round key with the saturation attack"""
        round_keys = aes.key_expansion(square.KEY, square.ROUNDS)
        last_round_key = square.recover_last_round_key()
        self.assertEqual(last_round_key, round_keys[-1])

    def test_key_contraction(self) -> None:
        """Given a round key, get the original key"""
        round_keys = aes.key_expansion(square.KEY, square.ROUNDS)
        for i in range(1, square.ROUNDS + 1):
            key = square.key_contraction(round_keys[i], i)
            self.assertEqual(key, square.KEY)

    @unittest.skip("long test")
    def test_square_attack(self) -> None:
        """End to end Square attack on mini-AES"""
        self.assertEqual(square.attack(), square.KEY)


if __name__ == "__main__":
    unittest.main(verbosity=2)
