# Ouf of the Sbox - Crypto 500 - 14 solves

Insomni'hack Teaser 2020

### Challenge description

```
Rijndael is too mainstream, so we went custom.
This should work out of the box and be unbreakable!

Authors: pwndawan & nico
```

Attached file: `out_of_the_sbox.zip`

### Offline Analysis

The Python source code attached to the challenge described a custom cipher that has the following properties (`des.py`):

* 64-bit blocks,
* 48-bit keys,
* 7-round balanced Feistel structure (two 32-bit branches),
* The F-function of the Feistel network is word-based:
	* Four key bytes are XORed to the 4-bytes input,
	* Four round-dependent Sboxes are applied to the 4 bytes,
	* The bytes are rotated by one position.

F-function:

```
(x0, x1, x2, x3) -> (S1[x1 + k1], S2[x2 + k2], S3[x3 + k3], S0[x0 + k0])
```

Cryptographically speaking, one can already pinpoints several weaknesses:

* There are only 7 rounds.
* The Sboxes chosen are linearly weak (the maximal biais is significantly high)
* There is no key schedule: the 6 bytes of the master key `k0 || k1 || k2 || k3 || k4 || k5` are used to construct the seven 32-bit subkeys:
	* `k2 || k3 || k4 || k5`
	* `k0 || k1 || k2 || k3`
	* `k4 || k5 || k0 || k1`
	* `k2 || k3 || k4 || k5`
	* `k0 || k1 || k2 || k3`
	* `k4 || k5 || k0 || k1`
	* `k2 || k3 || k4 || k5`
* There are only three difference subkeys `RK0`, `RK1` and `RK2`, which are used in a cyclic way.

### Online Analysis

Upon connection to the remote service, we are given 50,000 known plaintexts. I believe that the authors of the challenge wanted the solution to implement an attack based on linear cryptanalysis, relying on the very strong linear approximations existing in the Sboxes.

### Solution

The solution given below:

* does not implement a linear attack,
* is **independent of the choice of the Sboxes**,
* only requires **2 known plaintext/ciphertext pairs**.

The first pair is denoted `(P, C)` and will be used for the key recovery, while the second `(P', C')` is denoted and will only be used to filter out wrong key candidates by trial encryption of `P'`.

By guessing completely 32 bits of the master key (i.e., `k2 || k3 || k4 || k5`), one can partially encrypt and decrypt `P` and `C` to peel of the first and the last rounds. So we end up with a 5-round Feistel cipher where we also know partial subkey. We only have to recover the missing 16 bits of the master key.

To do this, we propagate the known information from the plaintext and the subkeys inwards, and simarly backwards from the ciphertext side. Since there are only five rounds, one can deduce a candidate value for `k0` as:

```
k0 = state[4][2] ^ invS_4_1[ state[4][5] ^ state[5][1] ]
```

where `state[r][i]` contains the `i`-th byte of the internal state after `r+1` rounds, and `invS_4_1` is the inverse of the Sbox `S[4][1]`.

We can the proceed similarly to derive a candidate for `k1`:

```
k1 = state[1][3] ^ invS_2_0[ state[0][2] ^ state[2][2] ]
```

Overall the pseudo code of the attack is:

```
For each value of (k2, k3, k4, k5)
    - Determine k0
    - Determine k1
    - If Encrypt(P', (k0, k1, k2, k3, k4, k5)) == C':
    	- Return k0, k1, k2, k3, k4, k5
```

Therefore the cost of the attack is equivalent to `2**32` encryptions, requires 2 KP, and has negligibly memory complexity.

Code of the attack is attached (`attack.c`).

#### Flag

`INS{W3ll_m4ybe_cust0m_5B0Xes_4re_no7_a_g0od_1dea!}`