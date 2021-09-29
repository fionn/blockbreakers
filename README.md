# Block Breakers

## Overview

### AES

A dangerous implementation of AES-128, with a parameterisable number of rounds for experimentation.

### SQUARE

The SQUARE/saturation attack on mini-AES (4 rounds), based primarily on the excellent [Block Breakers](https://www.davidwong.fr/blockbreakers/).

## Usage

### Test

Run unit tests with `make test`, which will test the AES implementation as well as components of the SQUARE attack.
The attack itself and the last round key recovery are skipped due to their long test times (~45 seconds on my machine).

### Attack

The attack is wrapped inside `square.attack`, which takes no arguments.

The oracle `square.setup` returns encrypted Λ-sets via `square.gen_lambda_set`, using the constant `square.KEY`.
These are used throughout the process.

`square.attack` cracks this key using repeated calls to the oracle.

It can be run directly with `./square.py`, which will assert correctness and print the recovered key.

## Resources

* [Block Breakers](https://www.davidwong.fr/blockbreakers/)
* [AES Specification](https://csrc.nist.gov/csrc/media/publications/fips/197/final/documents/fips-197.pdf)
* [Analysis of Recent Attacks on AES, §4.2](https://diglib.tugraz.at/download.php?id=576a78078c529&location=browse#section.4.2)
* [Improved Cryptanalysis of Rijndael, §2](https://www.schneier.com/wp-content/uploads/2009/07/paper-rijndael-2.pdf#page=2)
* [Integral Cryptanalysis](https://www.iacr.org/archive/fse2002/23650114/23650114.pdf)
* [The Block Cipher SQUARE, §6](https://cse.iitkgp.ac.in/~debdeep/courses_iitkgp/Crypto/papers/square.pdf#page=11)
