#!/usr/bin/env python3
"""Unit tests"""

import unittest

from aes import AES

class TestAES(unittest.TestCase):
    """Tests for AES"""

    def test_rot_word(self) -> None:
        """Test circular shift"""
        word = b"\x00\x01\x02\x03"
        self.assertEqual(AES.rot_word(word), b"\x01\x02\x03\x00")

    def test_rot_word_too_long(self) -> None:
        """Test circular shift with 5 bytes"""
        word = b"\x00\x01\x02\x03\x04"
        with self.assertRaises(AssertionError):
            AES.rot_word(word)

    def test_rot_word_too_short(self) -> None:
        """Test circular shift with 3 bytes"""
        word = b"\x00\x01\x02"
        with self.assertRaises(AssertionError):
            AES.rot_word(word)

    def test_sub_word(self) -> None:
        """Test subword against test vectors"""
        word = b"\x01\xc2\x9e\x00"
        self.assertEqual(AES.sub_word(word), b"\x7c\x25\x0b\x63")

    def test_rcon(self) -> None:
        """Test rcon against test vectors"""
        self.assertEqual(AES.rcon(1), [b"\x01", b"\x00", b"\x00", b"\x00"])
        self.assertEqual(AES.rcon(2), [b"\x02", b"\x00", b"\x00", b"\x00"])
        self.assertEqual(AES.rcon(3), [b"\x04", b"\x00", b"\x00", b"\x00"])
        self.assertEqual(AES.rcon(4), [b"\x08", b"\x00", b"\x00", b"\x00"])

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
        subkeys = AES.key_expansion(bytes.fromhex(test_subkeys[0]))
        self.assertEqual([key.hex() for key in subkeys], test_subkeys)

    def test_sub_bytes(self) -> None:
        """Test the SubBytes transformation"""
        data = bytes(range(16))
        data_prime = AES.sub_bytes(data)
        self.assertEqual(data_prime,
                         bytes.fromhex("637c777bf26b6fc53001672bfed7ab76"))

    def test_shift_rows(self) -> None:
        """Test the ShiftRows transformation"""
        data = bytes.fromhex("637c777bf26b6fc53001672bfed7ab76")
        data_prime = AES.shift_rows(data)
        self.assertEqual(data_prime,
                         bytes.fromhex("636b6776f201ab7b30d777c5fe7c6f2b"))

    def test_mix_columns(self) -> None:
        """Test the MixColumns transformation"""
        data = bytes.fromhex("636b6776f201ab7b30d777c5fe7c6f2b")
        data_prime = AES.mix_columns(data)
        self.assertEqual(data_prime,
                         bytes.fromhex("6a6a5c452c6d3351b0d95d61279c215c"))

    def test_add_round_key(self) -> None:
        """Test adding the round key"""
        data = bytes.fromhex("6a6a5c452c6d3351b0d95d61279c215c")
        key = bytes.fromhex("d6aa74fdd2af72fadaa678f1d6ab76fe")
        data_prime = AES.add_round_key(key, data)
        self.assertEqual(data_prime,
                         bytes.fromhex("bcc028b8fec241ab6a7f2590f13757a2"))

    def test_round(self) -> None:
        """End to end test for all the round functions"""
        data = bytes(range(16))
        key = bytes.fromhex("d6aa74fdd2af72fadaa678f1d6ab76fe")
        data = AES.sub_bytes(data)
        data = AES.shift_rows(data)
        data = AES.mix_columns(data)
        data = AES.add_round_key(key, data)
        self.assertEqual(data,
                         bytes.fromhex("bcc028b8fec241ab6a7f2590f13757a2"))

    def test_encryption(self) -> None:
        """Test AES encryption"""
        message = b"theblockbreakers"
        key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
        ciphertext = AES.encrypt(message, key)
        self.assertEqual(ciphertext,
                         bytes.fromhex("c69f25d0025a9ef32393f63e2f05b747"))

    def test_encryption_with_test_vector(self) -> None:
        """Test AES encryption with test vector from appendix C.1"""
        message = bytes.fromhex("00112233445566778899aabbccddeeff")
        key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
        ciphertext = AES.encrypt(message, key)
        self.assertEqual(ciphertext,
                         bytes.fromhex("69c4e0d86a7b0430d8cdb78070b4c55a"))

if __name__ == "__main__":
    unittest.main(verbosity=2)