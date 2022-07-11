---
title: "Encrypt-then-MAC for Committing AEAD (cAEAD)"
docname: draft-lucas-generalised-committing-aead-latest
category: info

ipr: trust200902
keyword: Internet-Draft

stand_alone: yes
smart_quotes: yes
pi: [toc, sortrefs, symrefs]

author:
 -
    name: Samuel Lucas
    organization: Individual Contributor
    email: samuel-lucas6@pm.me

informative:

  ADGKLS22:
    title: "How to Abuse and Fix Authenticated Encryption Without Key Commitment"
    rc: "31st USENIX Security Symposium (USENIX Security 22)"
    target: https://www.usenix.org/conference/usenixsecurity22/presentation/albertini
    author:
      -
        ins: A. Albertini
        name: Ange Albertini
        org: Google
      -
        ins: T. Duong
        name: Thai Duong
        org: Google
      -
        ins: S. Gueron
        name: Shay Gueron
        org: University of Haifa; Amazon
      -
        ins: S. Kölbl
        name: Stefan Kölbl
        org: Google
      -
        ins: A. Luykx
        name: Atul Luykx
        org: Google
      -
        ins: S. Schmieg
        name: Sophie Schmieg
        org: Google
    date: 2022

  BH22:
    title: "Efficient Schemes for Committing Authenticated Encryption"
    rc: "EUROCRYPT 2022. Lecture Notes in Computer Science, vol 13276, pp. 845-875"
    target: https://eprint.iacr.org/2022/268
    seriesinfo:
      DOI: 10.1007/978-3-031-07085-3_29
    author:
      -
        ins: M. Bellare
        name: Mihir Bellare
        org: University of California
      -
        ins: V. T. Hoang
        name: Viet Tung Hoang
        org: Florida State University
    date: 2022

  LGR21:
    title: "Partitioning Oracle Attacks"
    rc: "30th USENIX Security Symposium (USENIX Security 21), pp. 195–212"
    target: https://www.usenix.org/conference/usenixsecurity21/presentation/len
    author:
      -
        ins: J. Len
        name: Julia Len
        org: Cornell Tech
      -
        ins: P. Grubbs
        name: Paul Grubbs
        org: Cornell Tech
      -
        ins: T. Ristenpart
        name: Thomas Ristenpart
        org: Cornell Tech
    date: 2021

  GLR17:
    title: "Message Franking via Committing Authenticated Encryption"
    rc: "CRYPTO 2017. Lecture Notes in Computer Science, vol 10403, pp. 66-97"
    target: https://eprint.iacr.org/2017/664
    seriesinfo:
      DOI: 10.1007/978-3-319-63697-9_3
    author:
      -
        ins: P. Grubbs
        name: Paul Grubbs
        org: Cornell Tech
      -
        ins: J. Lu
        name: Jiahui Lu
        org: Shanghai Jiao Tong University
      -
        ins: T. Ristenpart
        name: Thomas Ristenpart
        org: Cornell Tech
    date: 2017

  BN00:
    title: "Authenticated encryption: Relations among notions and analysis of the generic composition paradigm"
    rc: "ASIACRYPT 2000. Lecture Notes in Computer Science, vol 1976, pp. 531-545"
    target: https://eprint.iacr.org/2000/025
    seriesinfo:
      DOI: 10.1007/3-540-44448-3_41
    author:
      -
        ins: M. Bellare
        name: Mihir Bellare
        org: University of California
      -
        ins: C. Namprempre
        name: Chanathip Namprempre
        org: Thammasat University
    date: 2000

--- abstract

This document describes how to construct a committing authenticated encryption with associated data (cAEAD) algorithm by combining an unauthenticated cipher and collision-resistant, hash-based message authentication code (MAC).

--- middle

# Introduction

A limitation of many existing AEAD schemes, such as ChaCha20-Poly1305 {{!RFC8439}}, is that they are not key- or message-committing, which has been condensed to the phrase "committing" for this document. This means it is possible for authentication to pass for multiple different keys. Thus, a ciphertext can be successfully decrypted to different plaintexts {{ADGKLS22}}. An attacker who knows the key can also manipulate another party into believing they have been sent a certain message when they actually possess a different message.

This has led to practical attacks, such as the partitioning oracle attack {{LGR21}}, which can allow an attacker to guess many encryption passwords at once by repeatedly providing a ciphertext that successfully decrypts under different keys to an oracle (e.g. a server that knows the encryption key). Such a ciphertext that potentially decrypts under thousands of keys can be quickly computed by an attacker, although the complexity and scalability of attacks depends on the AEAD. This exploits a lack of key commitment and may be extendable to other online scenarios, such as discovering which public key is being used from a set of public keys.

Another type of attack was demonstrated on Facebook Messenger's message franking scheme {{GLR17}}, which exploited a lack of message commitment. Due to end-to-end encryption, Facebook does not know a recipient's key. Therefore, when reporting a received message as abusive, the recipient must send their key for verification. However, a fake key could be used by the recipient to transform a harmless message from the sender into an abusive one.

Whilst such attacks only apply in certain scenarios, developers intuitively expect an AEAD to have this commitment property, increasing the risk of falling prey to this type of protocol vulnerability. Certain suggested mitigations must be built into cryptographic libraries, developers may be unaware of mitigations they can do themselves, and some mitigations may leak information. For example, encrypting zeros in the first block may lead to timing differences during decryption, and prepending an unsalted hash of the key leaks its identity.

However, Encrypt-then-MAC with the encryption key and authentication key derived from the same input keying material and a 256-bit or greater authentication tag from a collision-resistant, hash-based MAC is committing {{GLR17}}. Encrypt-then-MAC has been widely used (e.g. it forms the basis of ChaCha20-Poly1305), is well analysed {{BN00}}, can offer additional security against forgeries thanks to the larger tag, and can be more performant than some existing AEAD schemes under certain circumstances (e.g. depending on the MAC and size of the message).

The partitioning oracle attack authors recommend using a committing AEAD (cAEAD) by default when non-committing AEAD vulnerabilities cannot be ruled out {{LGR21}}. Therefore, this document introduces a simple Encrypt-then-MAC cAEAD scheme that can be implemented using an unauthenticated cipher and collision-resistant, hash-based MAC from a cryptographic library. For instance, ChaCha20 {{!RFC8439}} and BLAKE2b {{!RFC7693}} could be used.

# Conventions and Definitions

{::boilerplate bcp14-tagged}

Operations:

- `a || b`: the concatenation of `a` and `b`.
- `a.Length`: the length of `a` in octets.
- `LE64(x)`: the little-endian encoding of 64-bit unsigned integer `x`.
- `UTF8(s)`: the UTF8 encoding of string `s`.
- `a.Slice(i, l)`: the copy of `l` bytes from `a`, starting at index `i`.
- `Encrypt(p, n, k)`: the unauthenticated encryption of plaintext `p` using nonce `n` and key `k`.
- `MAC(m, k, l)`: the `l` bits MAC of message `m` using key `k`.
- `ConstantTimeEquals(a, b)`: the constant time comparison of `a` and `b`, which returns `true` if equal and `false` otherwise.
- `Decrypt(c, n, k)`: the unauthenticated decryption of ciphertext `c` without the appended tag using nonce `n` and key `k`.
- `ZeroMemory(a)`: overwrite `a` with zeros in a way that is not optimised away by the compiler.

Internals:

- `ENCRYPTION_CONTEXT`: "Cipher.Encrypt()", replacing "Cipher" with the properly capitalised and punctuated name of the cipher being used. For example, "ChaCha20.Encrypt()" or "AES-CTR.Encrypt()".
- `MAC_CONTEXT`: "MAC.KeyedHash()", replacing "MAC" with the properly capitalised and punctuated name of the MAC being used. For example, "BLAKE2b.KeyedHash()" or "HMAC-SHA256.KeyedHash()".
- `T_LEN`: the authentication tag length, which MUST be 32 octets (256 bits).

Inputs and outputs:

- `K_LEN`: the key length, which MUST be 32 octets (256 bits).
- `N_MIN`/`N_MAX`: the nonce length, which MUST be the maximum nonce length supported by the cipher being used. For example, 12 octets (96 bits) for ChaCha20 {{!RFC8439}}.
- `A_MAX`: 2<sup>64</sup>-1 octets.
- `P_MAX`: 2<sup>64</sup>-1 octets unless the cipher being used requires a smaller plaintext to avoid the internal counter repeating or a collision being likely with a 50% probability. For example, 274,877,906,880 octets MUST be the maximum for ChaCha20 {{!RFC8439}}.
- `C_MAX`: `P_MAX` + `T_LEN`.

The meanings of these parameters are defined in {{!RFC5116, Section 4}}.

# The Generalised cAEAD Construction

This construction combines two primitives:

1. An unauthenticated stream cipher or block cipher.
2. A collision-resistant keyed hash function or collision-resistant hash function used within HMAC {{!RFC2104}}.

Importantly, the MAC MUST be hash-based and collision resistant. This ensures the ciphertext is a commitment of all the inputs, corresponding to security notion CMT-4 {{BH22}}. This provides the best security and ease of use by default.

## Authenticated Encryption

~~~
Encrypt(plaintext, nonce, key, associatedData)
~~~

The `Encrypt` function encrypts a plaintext message, authenticates the ciphertext and associated data, and returns the ciphertext concatenated with the authentication tag.

Inputs:

- `plaintext`: the plaintext to be encrypted (length MUST be less than `P_MAX`).
- `nonce`: the public nonce (length MUST be N_MIN).
- `key`: the secret key (length MUST be K_LEN).
- `associatedData`: the associated data to authenticate (length MUST be less than `A_MAX`).

Distinct associated data inputs, as described in {{!RFC5116, Section 3}} will be unambiguously encoded as a single input. The application MUST create a structure in the associated data input if needed.

Outputs:

- The ciphertext concatenated with the authentication tag or an error if the inputs do not meet the length criteria above.

Steps:

~~~
encryptionKey = MAC(UTF8(ENCRYPTION_CONTEXT), key, K_LEN)
macKey = MAC(UTF8(MAC_CONTEXT) || nonce, key, K_LEN)

ciphertext = Encrypt(plaintext, nonce, encryptionKey)

tag = MAC(associatedData || ciphertext || LE64(associatedData.Length) || LE64(ciphertext.Length), macKey, T_LEN)

ZeroMemory(encryptionKey)
ZeroMemory(macKey)

return ciphertext || tag
~~~

## Authenticated Decryption

~~~
Decrypt(ciphertext, nonce, key, associatedData)
~~~

The `Decrypt` function verifies that the authentication tag is correct for the given inputs and returns the decrypted ciphertext on success or an error if verification fails.

Inputs:

- `ciphertext`: the ciphertext and appended tag to be authenticated and decrypted (length MUST be less than `C_MAX`).
- `nonce`: the public nonce (length MUST be N_MIN).
- `key`: the secret key (length MUST be K_LEN).
- `associatedData`: the associated data to authenticate (length MUST be less than `A_MAX`).

Outputs:

- Either the decrypted plaintext or an error indicating that the authentication tag is invalid for the given inputs.

Steps:

~~~
tag = ciphertext.Slice(ciphertext.Length - T_LEN, T_LEN)

ciphertextNoTag = ciphertext.Slice(0, ciphertext.Length - T_LEN)

encryptionKey = MAC(UTF8(ENCRYPTION_CONTEXT), key, K_LEN)
macKey = MAC(UTF8(MAC_CONTEXT) || nonce, key, K_LEN)

computedTag = MAC(associatedData || ciphertextNoTag || LE64(associatedData.Length) || LE64(ciphertextNoTag.Length), macKey, T_LEN)

ZeroMemory(macKey)

if (ConstantTimeEquals(tag, computedTag) == false)
    ZeroMemory(encryptionKey)
    return "authentication failed" error
else
    plaintext = Decrypt(ciphertextNoTag, nonce, encryptionKey)
    ZeroMemory(encryptionKey)
    return plaintext
~~~

# ChaCha20-BLAKE2b

This algorithm is an instantiation of the generalised cAEAD scheme discussed above using ChaCha20 {{!RFC8439}} as the cipher and BLAKE2b {{!RFC7693}} as the MAC.

The ChaCha20 specific input and output lengths are:

- `N_MIN`/`N_MAX`: 12 octets.
- `P_MAX`: 2<sup>38</sup> octets.
- `C_MAX`: 2<sup>38</sup> + `T_LEN` octets.

The rest of the lengths remain the same for all instantiations of this generalised cAEAD scheme.

The context strings are:

- `ENCRYPTION_CONTEXT`: "ChaCha20.Encrypt()".
- `MAC_CONTEXT`: "BLAKE2b.KeyedHash()".

# Security Considerations

The security of this generalised scheme depends on the unauthenticated cipher and collision-resistant, hash-based MAC used. For instance, ChaCha20 should provide 256-bit security against plaintext recovery, and HMAC-SHA256 should provide 256-bit security against forgery attacks. A 256-bit tag provides 128-bit security against collisions. This collision resistance should make it infeasible for a ciphertext to be decrypted under multiple keys.

The nonce MUST NOT be repeated or reused for a given key. Doing so is catastrophic for security. For example, it results in identical keystreams with stream ciphers, which leaks the XOR of the plaintexts.

The authentication tag comparison MUST be done in constant time to avoid leaking information via timing.

If authentication fails, the ciphertext MUST NOT be decrypted internally, and the decrypted plaintext MUST NOT be given as output.

The authentication tag MUST NOT be truncated as this would affect the collision resistance, which is needed for this scheme to be committing.

Every key MUST be randomly chosen from a uniform distribution. Keys can either be randomly generated using a cryptographically secure pseudorandom number generator (CSPRNG) or the output of a key derivation function (KDF).

The nonce MAY be public and/or predictable. It can be a counter, the output of a KDF by deriving a secret key alongside the nonce, or randomly generated using a CSPRNG. However, care MUST be taken to ensure that the likelihood of two randomly generated nonces colliding is low by frequently rotating the key being used.

The internally derived `encryptionKey` and `macKey` SHOULD be erased from memory before returning an output. However, this may not be possible in some programming languages.

# IANA Considerations

IANA is requested to assign an entry for `AEAD_ChaCha20_BLAKE2b` in the AEAD Registry with this document as the reference.

--- back

# Test Vectors

## ChaCha20-BLAKE2b

### Test Vector 1

~~~
plaintext: 5468657265277320736f6d6520676f6f6420696e207468697320776f726c642c204d722e2046726f646f2c20616e64206974277320776f727468206669676874696e6720666f722e

nonce: 000000000000000000000000

key: 1001000000000000000000000000000000000000000000000000000000000000

associatedData:

ciphertext: 18337327ef02753bf8d996db218a3697c18943ea6efc86a7e449cb67a7592b9e1715a07771797c93789350528e2e7a8d25b4ca7a7d2968776d50577946cb5da693f1e09309236b7b7495a49a834611b4e67e02d5b24b8a538010ed6c43c30d0f172afe807c064855
~~~

### Test Vector 2

~~~
plaintext:

nonce: 000000000000000000000000

key: 1001000000000000000000000000000000000000000000000000000000000000

associatedData:

ciphertext: d4ad4bb5a97e0cf9eae5b695ee8f2c3e040241372a28c407abe1fe9accf94d04
~~~

### Test Vector 3

~~~
plaintext:

nonce: 000000000000000000000000

key: 1001000000000000000000000000000000000000000000000000000000000000

associatedData: 76312e302e30

ciphertext: e048f6d38e774c50e143d422d6d6bf0c970d161aaa32f80145c63e876b470f86
~~~

### Test Vector 4

~~~
plaintext: 5468657265277320736f6d6520676f6f6420696e207468697320776f726c642c204d722e2046726f646f2c20616e64206974277320776f727468206669676874696e6720666f722e

nonce: 010000000000000000000000

key: 1001000000000000000000000000000000000000000000000000000000000000

associatedData:

ciphertext: db685e0ff12fafd611a832c90e6c7905598ed65babdf6d8cf7057d07b5168673727dda3ef3d6ed2520332c8036e2ce0f72c413290bc4ae41d2d398e4cb2d1f6e906e232ae471ca0e6c12488063dd83b2b45b85d0e9919c420cb64b01a0b49e7189fc3c14e606ac8b
~~~

### Test Vector 5

~~~
plaintext: 5468657265277320736f6d6520676f6f6420696e207468697320776f726c642c204d722e2046726f646f2c20616e64206974277320776f727468206669676874696e6720666f722e

nonce: 000000000000000000000000

key: 1002000000000000000000000000000000000000000000000000000000000000

associatedData:

ciphertext: 308319762a72faf302e6d34c2f882c27addc1b2130549e55a084bcdc189c2da0497fdbab20989f24a25f2d3934ac825caaf46ec61a853a06eb97b14c2ced147b94c2223506862d32e183e771eb4a3a03c1875934176577066552fffac50022b3925b9640b4c2d578
~~~

### Test Vector 6

This test MUST return an "authentication failed" error.

~~~
ciphertext: 408319762a72faf302e6d34c2f882c27addc1b2130549e55a084bcdc189c2da0497fdbab20989f24a25f2d3934ac825caaf46ec61a853a06eb97b14c2ced147b94c2223506862d32e183e771eb4a3a03c1875934176577066552fffac50022b3925b9640b4c2d578

nonce: 000000000000000000000000

key: 1002000000000000000000000000000000000000000000000000000000000000

associatedData:
~~~

### Test Vector 7

This test MUST return an "authentication failed" error.

~~~
ciphertext: 308319762a72faf302e6d34c2f882c27addc1b2130549e55a084bcdc189c2da0497fdbab20989f24a25f2d3934ac825caaf46ec61a853a06eb97b14c2ced147b94c2223506862d32e183e771eb4a3a03c1875934176577066552fffac50022b3925b9640b4c2d579

nonce: 000000000000000000000000

key: 1002000000000000000000000000000000000000000000000000000000000000

associatedData:
~~~

### Test Vector 8

This test MUST return an "authentication failed" error.

~~~
ciphertext: 308319762a72faf302e6d34c2f882c27addc1b2130549e55a084bcdc189c2da0497fdbab20989f24a25f2d3934ac825caaf46ec61a853a06eb97b14c2ced147b94c2223506862d32e183e771eb4a3a03c1875934176577066552fffac50022b3925b9640b4c2d578

nonce: 000000000000000000000001

key: 1002000000000000000000000000000000000000000000000000000000000000

associatedData:
~~~

### Test Vector 9

This test MUST return an "authentication failed" error.

~~~
ciphertext: 308319762a72faf302e6d34c2f882c27addc1b2130549e55a084bcdc189c2da0497fdbab20989f24a25f2d3934ac825caaf46ec61a853a06eb97b14c2ced147b94c2223506862d32e183e771eb4a3a03c1875934176577066552fffac50022b3925b9640b4c2d578

nonce: 000000000000000000000000

key: 1003000000000000000000000000000000000000000000000000000000000000

associatedData:
~~~

### Test Vector 10

This test MUST return an "authentication failed" error.

~~~
ciphertext: 308319762a72faf302e6d34c2f882c27addc1b2130549e55a084bcdc189c2da0497fdbab20989f24a25f2d3934ac825caaf46ec61a853a06eb97b14c2ced147b94c2223506862d32e183e771eb4a3a03c1875934176577066552fffac50022b3925b9640b4c2d578

nonce: 000000000000000000000000

key: 1002000000000000000000000000000000000000000000000000000000000000

associatedData: 76312e302e30
~~~

# Acknowledgments
{:numbered="false"}

ChaCha20 and Poly1305 were designed by Daniel J. Bernstein.

BLAKE2 was designed by Jean-Philippe Aumasson, Samuel Neves, Zooko Wilcox-O'Hearn, and Christian Winnerlein.

HMAC was designed by Mihir Bellare, Ran Canetti, and Hugo Krawczyk.
