#!/usr/bin/env python3
# -*- coding: utf-8 -*-

I = "alice"
P = "password123"
s = "7953b2be1e58a8d16727a7b5ee41243a"

a = "27559760adf25c036f8089190b21070404dc1ec8562a76e2dd29d5af93432dda"
b = "59cb87e450c51ad3f0811e47e028690fe908da1df404a074d1f5619e204d2805"


N3072 = "ffffffff ffffffff c90fdaa2 2168c234 c4c6628b 80dc1cd1 29024e08"\
        "8a67cc74 020bbea6 3b139b22 514a0879 8e3404dd ef9519b3 cd3a431b"\
        "302b0a6d f25f1437 4fe1356d 6d51c245 e485b576 625e7ec6 f44c42e9"\
        "a637ed6b 0bff5cb6 f406b7ed ee386bfb 5a899fa5 ae9f2411 7c4b1fe6"\
        "49286651 ece45b3d c2007cb8 a163bf05 98da4836 1c55d39a 69163fa8"\
        "fd24cf5f 83655d23 dca3ad96 1c62f356 208552bb 9ed52907 7096966d"\
        "670c354e 4abc9804 f1746c08 ca18217c 32905e46 2e36ce3b e39e772c"\
        "180e8603 9b2783a2 ec07a28f b5c55df0 6f4c52c9 de2bcbf6 95581718"\
        "3995497c ea956ae5 15d22618 98fa0510 15728e5a 8aaac42d ad33170d"\
        "04507a33 a85521ab df1cba64 ecfb8504 58dbef0a 8aea7157 5d060c7d"\
        "b3970f85 a6e1e4c7 abf5ae8c db0933d7 1e8c94e0 4a25619d cee3d226"\
        "1ad2ee6b f12ffa06 d98a0864 d8760273 3ec86a64 521f2b18 177b200c"\
        "bbe11757 7a615d6c 770988c0 bad946e2 08e24fa0 74e5ab31 43db5bfc"\
        "e0fd108e 4b82d120 a93ad2ca ffffffff ffffffff"

g3072 = 5


import hashlib
import numpy


def sha(s):
    return hashlib.sha512(s).digest()

def srp_verifier(g, N, salt, user, password):
    sep = ":".encode()
    x = sha(user + sep + password)
    x = sha(salt + x)
    x = int.from_bytes(x, "big")
    return pow(g, x, N)

def srp_public_key(g, N, k, b, v):
    bi = int.from_bytes(b, "big")
    return (k * v + pow(g, bi, N)) % N

def srp_public_key_cli(g, N, a):
    ai = int.from_bytes(a, "big")
    return pow(g, ai, N)

def srp_scrambling_parameter(A, B):
    Ai = A.to_bytes((A.bit_length() + 7) // 8, "big")
    Bi = B.to_bytes((B.bit_length() + 7) // 8, "big")
    return sha(Ai + Bi)

def srp_premaster_secret(N, A, b, u, v):
    ui = int.from_bytes(u, "big")
    bi = int.from_bytes(b, "big")
    return pow(A * pow(v, ui, N), bi, N)

def srp_session_key(s):
    si = s.to_bytes((s.bit_length() + 7) // 8, "big")
    return sha(si)

def srp_proof_m1(g, N, user, salt, A, B, k):
    Ni = N.to_bytes((N.bit_length() + 7) // 8, "big")
    gi = g.to_bytes((g.bit_length() + 7) // 8, "big")
    HN = sha(Ni);
    Hg = sha(gi);
    HNi = int.from_bytes(HN, "big")
    Hgi = int.from_bytes(Hg, "big")
    Hng = HNi ^ Hgi
    Hngi = Hng.to_bytes((Hng.bit_length() + 7) // 8, "big")
    print("constant part Hng: 0x" + "".join("{:02X}".format(x) for x in Hngi)) # constant for hash and group
    
    HU = sha(user)
    Ai = A.to_bytes((A.bit_length() + 7) // 8, "big")
    Bi = B.to_bytes((B.bit_length() + 7) // 8, "big")
    return sha(Hngi + HU + salt + numpy.trim_zeros(Ai) + numpy.trim_zeros(Bi) + k)

def srp_proof_m2(A, m1, k):
    Ai = A.to_bytes((A.bit_length() + 7) // 8, "big")
    return sha(numpy.trim_zeros(Ai) + m1 + k)

# https://en.wikipedia.org/wiki/Secure_Remote_Password_protocol#RFCs
def main():
    N = int("".join(N3072.split()).replace(" ", ""), 16)
    g = g3072
    tmp_g = bytearray(384)
    tmp_g[383] = g3072
    k = int.from_bytes(sha(N.to_bytes((N.bit_length() + 7) // 8, "big") + tmp_g), "big")
    print("group: " + hex(N))
    print("generator: " + hex(g))
    print("multiplier: " + hex(k))

    user_name = I.encode()
    user_pass = P.encode()
    salt = bytes.fromhex(s)
    print("username: 0x" + "".join("{:02X}".format(x) for x in user_name))
    print("userpass: 0x" + "".join("{:02X}".format(x) for x in user_pass))
    print("salt: 0x" + "".join("{:02X}".format(x) for x in salt))

    verifier = srp_verifier(g, N, salt, user_name, user_pass)
    print("verifier: " + hex(verifier))

    pri_b = bytes.fromhex(b)
    print("pri b: 0x" + "".join("{:02X}".format(x) for x in pri_b))
    pub_b = srp_public_key(g, N, k, pri_b, verifier)
    print("pub b: " + hex(pub_b))
    
    pri_a = bytes.fromhex(a)
    print("pri a: 0x" + "".join("{:02X}".format(x) for x in pri_a))
    pub_a = srp_public_key_cli(g, N, pri_a)
    print("pub a: " + hex(pub_a))
    
    scrambling = srp_scrambling_parameter(pub_a, pub_b)
    print("scrambling: 0x" + "".join("{:02x}".format(x) for x in scrambling))
    
    secret = srp_premaster_secret(N, pub_a, pri_b, scrambling, verifier)
    print("secret: " + hex(secret))
    
    session_key = srp_session_key(secret)
    print("session key: 0x" + "".join("{:02x}".format(x) for x in session_key))
    
    proof_m1 = srp_proof_m1(g, N, user_name, salt, pub_a, pub_b, session_key)
    print("proof m1: 0x" + "".join("{:02x}".format(x) for x in proof_m1))
    
    proof_m2 = srp_proof_m2(pub_a, proof_m1, session_key)
    print("proof m2: 0x" + "".join("{:02x}".format(x) for x in proof_m2))
    

# call main function
if __name__ == "__main__":
    main()