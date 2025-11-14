from secrets import compare_digest
import pqcrypto.kem.ml_kem_512 as kem
import pqcrypto.sign.sphincs_shake_256s_simple as signature
import pqcrypto
import secrets
import hashlib
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from pybulletproofs import zkrp_prove, zkrp_verify
from tinyec import registry
from ecdsa import ellipticcurve, curves
from dataclasses import dataclass
import time

@dataclass
class Account:
    public_key: bytes
    secret_key: bytes
    verification_key: bytes
    sign_key: bytes
    balance : int 
    rand : int
    commited_balance : object

@dataclass
class Transaction:
    ciphertext: bytes
    commitment: object
    nonce_value: bytes
    initial_value: bytes
    signature: bytes
    sender_verification_key: bytes
    encmsg: list[int]

#######################################################################################################

TXN_MSG_SIZE = 64  # Number of bits to represent transaction amount (e.g., up to 65535)
RAND_SIZE = 256     # Number of bits for randomness in Pedersen commitment

####THINGS TO DO:
#1. Switch to Ristretto Curve
#2. Add Bulletproofs to prove that the transaction amount is less than the sender's balance
#3. Hash_to_curve for H generation in Pedersen commitment
#4. Provide Proof of Correct Decryption if transaction is invalid


#######################################################################################################

# AES Helper Functions
def aes_prg_bitarray(seed: bytes, n_bits: int, nonce_value, initial_value) -> list[int]:
    """
    Generate n_bits pseudorandom bits using AES in CTR mode.
    Returns a bit array (list of 0/1 integers).
    """
    if len(seed) not in (16, 24, 32):
        raise ValueError("Seed must be 16, 24, or 32 bytes (AES-128/192/256).")

    # Number of bytes needed
    n_bytes = (n_bits + 7) // 8

    # AES in CTR mode acts like a secure PRG
    cipher = AES.new(seed, AES.MODE_CTR, nonce=nonce_value, initial_value=initial_value)

    # Encrypt a block of zeros → pseudorandom bytes
    stream = cipher.encrypt(b'\x00' * n_bytes)

    # Convert to bits
    bits = []
    for byte in stream:
        for i in range(8):
            bits.append((byte >> (7 - i)) & 1)  # MSB → LSB

    # Trim to exact number of bits
    return bits[:n_bits]


#######################################################################################################
# -------------------------------------------------------------
# Pedersen Commitment
# -------------------------------------------------------------

    

def point_to_bytes(P):
    x = P.x.to_bytes(32, 'big')
    prefix = b'\x02' if P.y % 2 == 0 else b'\x03'
    return prefix + x


def pedersen_setup():
    curve = registry.get_curve("secp256r1")   # You can pick other curves

    G = curve.g                               # Standard base point
    # Choose H as a random multiple of G (must be secret and independent)
    h_scalar = secrets.randbelow(curve.field.n)
    #H = hash_to_curve(b"this is my generator H")
    #Need to generate H using hash to curve
    H = h_scalar * G
    params = (curve, G, H)
    assert(params[1]==G)
    assert(params[2]==H)
    return params

def pedersen_commit(params, m: int):
    """
    Returns EC point: C = m*G + r*H
    """
    m = m % params[0].field.n  # Ensure m is in the field
    r = secrets.randbelow(params[0].field.n)  # Randomness
    C = m * params[1] + r * params[2]
    return (C, r)

def pedersen_verify(params, C, m: int, r: int) -> bool:
    """
    Verify that C is a commitment to m with randomness r.
    """
    lhs = C
    rhs = m * params[1] + r * params[2]
    return lhs == rhs


def add_commitments(params, c1: int, c2: int):
    return c1 + c2

def mult_scalar_commitments(params, c1: int, s: int):
    return s * c1

#######################################################################################################


# Helper: convert string <-> integer via SHA-256 (collision-resistant encoding)
def string_to_int(s: str) -> int:
    """Map arbitrary string to an integer (useful for committing to text)."""
    b = s.encode("utf-8")
    return int.from_bytes(hashlib.sha256(b).digest(), "big")

def int_to_hex_str(i: int) -> str:
    return hex(i)

#######################################################################################################

# Convert fixed bit array to int


def bitarray_to_fixed_int(bits: list[int], length: int) -> int:
    """
    Convert bit array to an integer with a fixed bit-length.
    Pads with leading zeros if needed.
    """
    if len(bits) > length:
        raise ValueError("Bit array longer than fixed length.")
    padded = [0] * (length - len(bits)) + bits  # pad left
    return int(''.join(str(b) for b in padded), 2)

# Convert int to fixed bit array

def int_to_fixed_bitarray(n: int, length: int) -> list[int]:
    """
    Convert integer to a bit array of exactly `length` bits.
    Pads with leading zeros.
    """
    if n < 0:
        raise ValueError("Only non-negative integers allowed.")
    bits = bin(n)[2:]
    if len(bits) > length:
        raise ValueError("Number too large for requested bit length.")
    bits = bits.zfill(length)
    return [int(b) for b in bits]


#XORing two bit arrays
def bitarray_add_mod2(a: list[int], b: list[int]) -> list[int]:
    """
    Adds two bit arrays modulo 2 (same as XOR).
    Bit arrays must be the same length.
    """
    if len(a) != len(b):
        raise ValueError("Bit arrays must have the same length.")

    return [(x ^ y) for x, y in zip(a, b)]

# Convert bytes to bits
def bytes_to_bits(b: bytes) -> str:
    """Convert bytes object to a string of bits ('0'/'1')."""
    return ''.join(f'{byte:08b}' for byte in b)


# Convert bit string to bytes
def bits_to_bytes(bitstring: str) -> bytes:
    """Convert string of bits ('0'/'1') back to bytes."""
    # Pad length to multiple of 8 if needed
    bitstring = bitstring.zfill((8 - len(bitstring) % 8) % 8 + len(bitstring))
    return int(bitstring, 2).to_bytes(len(bitstring) // 8, byteorder='big')

# String → bits
def string_to_bits(s: str) -> str:
    """Convert text string to its bit representation."""
    return ''.join(f'{ord(c):08b}' for c in s)

# Bits → string
def bits_to_string(bitstring: str) -> str:
    """Convert bit string ('0'/'1') back to text string."""
    chars = [chr(int(bitstring[i:i+8], 2)) for i in range(0, len(bitstring), 8)]
    return ''.join(chars)

# String → bytes
def str_to_bytes(s: str) -> bytes:
    """
    Converts a string to bytes using UTF-8 encoding.
    """
    return s.encode('utf-8')




#######################################################################################################
#Functions for Receiver 

#######################################################################################################
#Functions for Sender

#######################################################################################################



def setup_keys()->(object, Account, Account):
    params = pedersen_setup() #Generate Pedersen Commitment parameters

    # Receiver generates a (public, secret) key pair
    rec_public_key, rec_secret_key = kem.generate_keypair()

    # Receiver generates a (public, secret) key pair
    rec_verif_key, rec_sign_key = signature.generate_keypair()


    # Sender generates a (public, secret) key pair
    sen_public_key, sen_secret_key = kem.generate_keypair()

    # Sender generates a (public, secret) key pair
    sen_verif_key, sen_sign_key = signature.generate_keypair()

    rec_account = Account(public_key=rec_public_key, secret_key=rec_secret_key, verification_key=rec_verif_key, sign_key=rec_sign_key, balance=0, rand=0, commited_balance=None)

    sen_account = Account(public_key=sen_public_key, secret_key=sen_secret_key, verification_key=sen_verif_key, sign_key=sen_sign_key, balance=0, rand=0, commited_balance=None)

    return (params, rec_account, sen_account)
    
def setup_balances(params, rec_account, sen_account)->(Account, Account):
    # Initial balances    
    rec_balance = 1000
    sen_balance = 5000


    # Both parties commit to their balances
    rec_com, rec_rand = pedersen_commit(params, rec_balance)
    sen_com, sen_rand = pedersen_commit(params, sen_balance) 

    print("Initial Receiver's committed balance:", rec_balance)
    print("Initial Sender's committed balance:", sen_balance)

    assert(pedersen_verify(params, rec_com, rec_balance, rec_rand))  # Verifying Receiver's commitment to its balance
    assert(pedersen_verify(params, sen_com, sen_balance, sen_rand))  # Verifying Sender's commitment to its balance
    assert(pedersen_verify(params, add_commitments(params, rec_com, sen_com), rec_balance + sen_balance, rec_rand + sen_rand))  # Verifying sum of commitments

    rec_account.balance = rec_balance
    rec_account.rand = rec_rand
    rec_account.commited_balance = rec_com

    sen_account.balance = sen_balance
    sen_account.rand = sen_rand
    sen_account.commited_balance = sen_com

    return (rec_account, sen_account)



def send_transaction(params, txn_amount, sen_account, rec_public_key)->Transaction:

    txn_com, txn_rand = pedersen_commit(params, txn_amount)
    nonce_value = get_random_bytes(8)
    initial_value = int.from_bytes(get_random_bytes(8), byteorder='big')
    assert(pedersen_verify(params, txn_com, txn_amount, txn_rand))  # Should be True

    txn_amt_array= int_to_fixed_bitarray(txn_amount, TXN_MSG_SIZE)
    txn_rand_array= int_to_fixed_bitarray(txn_rand, RAND_SIZE)

    global sharedkey_original
    # Sender derives a secret (the plaintext) and encrypts it with Receiver's public key to produce a ciphertext
    ciphertext, sharedkey_original = kem.encrypt(rec_public_key)

    assert(len(txn_amt_array+txn_rand_array)==TXN_MSG_SIZE+RAND_SIZE)

    encmsg = bitarray_add_mod2(aes_prg_bitarray(sharedkey_original, TXN_MSG_SIZE+RAND_SIZE,nonce_value,initial_value), txn_amt_array+txn_rand_array)

    print("The transaction amount is", txn_amount)
    # Sender signs her message using her secret key to sign the transaction
    txn_sign = signature.sign(sen_account.sign_key, str_to_bytes(str(txn_com)+str(ciphertext)+str(nonce_value)+str(initial_value)))

    txn = Transaction(ciphertext=ciphertext, commitment=txn_com, nonce_value=nonce_value, initial_value=initial_value, signature=txn_sign, sender_verification_key=sen_account.verification_key, encmsg=encmsg)
    sen_account.balance = sen_account.balance - txn_amount
    sen_account.rand = sen_account.rand - txn_rand
    sen_account.commited_balance = add_commitments(params, sen_account.commited_balance, mult_scalar_commitments(params, txn_com, -1))
    assert(pedersen_verify(params, sen_account.commited_balance, sen_account.balance, sen_account.rand))  # Verifying updated Sender's commitment to its balance
    return txn

def receive_transaction(params, txn, rec_account):
    assert signature.verify(txn.sender_verification_key, str_to_bytes(str(txn.commitment)+str(txn.ciphertext)+str(txn.nonce_value)+str(txn.initial_value)), txn.signature)

    # Receiver decrypts Bob's ciphertext to derive the now shared secret
    sharedkey_recovered = kem.decrypt(rec_account.secret_key, txn.ciphertext)

    assert compare_digest(sharedkey_original, sharedkey_recovered)
    assert (aes_prg_bitarray(sharedkey_original, TXN_MSG_SIZE+RAND_SIZE,txn.nonce_value, txn.initial_value)== aes_prg_bitarray(sharedkey_recovered, TXN_MSG_SIZE+RAND_SIZE,txn.nonce_value, txn.initial_value))
    
    decmsg = bitarray_add_mod2(aes_prg_bitarray(sharedkey_recovered, TXN_MSG_SIZE+RAND_SIZE,txn.nonce_value, txn.initial_value), txn.encmsg)

    print("Decrypted Transaction amount:",bitarray_to_fixed_int(decmsg[:TXN_MSG_SIZE], TXN_MSG_SIZE))

    txn_amount = bitarray_to_fixed_int(decmsg[:TXN_MSG_SIZE], TXN_MSG_SIZE)
    txn_rand = bitarray_to_fixed_int(decmsg[TXN_MSG_SIZE:], RAND_SIZE)

    assert(pedersen_verify(params, txn.commitment, txn_amount, txn_rand))  # Verifying Transaction commitment with decrypted amount and randomness

    rec_balance = rec_account.balance

    #Update on-chain committed values, randomnesses and balances
    rec_account.balance += txn_amount
    rec_account.rand += +txn_rand
    rec_account.commited_balance = add_commitments(params, rec_account.commited_balance, txn.commitment)
    assert(pedersen_verify(params, rec_account.commited_balance, rec_account.balance, rec_account.rand))  # Verifying updated Receiver's commitment to its balance

    ##If the transaction is invalid then produce a proof of correct decryption without revealing the receiver's kem secret key###

def main():

    # Setup Keys
    start = time.perf_counter()
    params, rec_account, sen_account = setup_keys()

    end = time.perf_counter()
    print(f"Key Generation Time: {end - start:0.4f} seconds")

    
    #Setup balance
    start = time.perf_counter()
    rec_account, sen_account = setup_balances(params, rec_account, sen_account)
    end = time.perf_counter()
    print(f"Setup Balances Time: {end - start:0.4f} seconds")

    # Sender wants to send 100 to Receiver
    start = time.perf_counter()
    txn_amount = 100
    txn = send_transaction(params, txn_amount, sen_account, rec_account.public_key)
    end = time.perf_counter()
    print("Sender's new balance",sen_account.balance)
    print(f"Send Transaction Time: {end - start:0.4f} seconds")
    ### Sender sends txn=(ciphertext, txn_com, nonce_value, initial_value, txn_sign) to the Receiver to perform the transaction###

    # Receiver verifies transaction and updates its balance by 100
    start = time.perf_counter()
    receive_transaction(params, txn, rec_account)
    end = time.perf_counter()
    print("Receiver's new balance",rec_account.balance)
    print(f"Receive Transaction Time: {end - start:0.4f} seconds")
    
    ###Need to add Bulletproofs to prove that the transaction amount is less than the sender's balance###


if __name__ == "__main__":
    main()