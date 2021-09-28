"""Helper functions"""


def fixed_xor(a: bytes, b: bytes) -> bytes:
    """xor two byte strings"""
    assert len(a) == len(b), "Arguments must be of equal length"
    return bytes(i ^ j for (i, j) in zip(a, b))


def state_to_matrix(data: bytes) -> list[bytes]:
    """Represent internal state as a matrix, row by row"""
    return [data[4 * i: 4 * (i + 1)] for i in range(0, 4)]


def matrix_to_state(matrix: list[bytes]) -> bytes:
    """Flatten a matrix to a 16 byte word, row by row"""
    assert len(matrix) == 4
    return b"".join(matrix)


def transpose(matrix: list[bytes]) -> list[bytes]:
    """Matrix transposition"""
    return list(map(bytes, zip(*matrix)))


def to_bytes(x: int) -> bytes:
    """Wrapper mapping ints to bytes"""
    return x.to_bytes(max((x.bit_length() + 7) // 8, 1), "big")


def index_to_coordinate(x: int) -> tuple[int, int]:
    """Map byte index to state matrix coordinate (not transposed)"""
    assert x in range(16)
    return (x % 4, x // 4)


def coordinate_to_index(x: tuple[int, int]) -> int:
    """Map state matrix coordinate (not transposed) to byte index"""
    assert x[0] in range(4)
    assert x[1] in range(4)
    return 4 * x[1] + x[0]
