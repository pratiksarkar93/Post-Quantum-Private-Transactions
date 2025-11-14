This project focuses on constructing a post-quantum secure private transaction protocol using lattice-based KEM, Sphincs Signatures and Pedersen Commitment. The current implementation is done over Secpr1 curve and does not provide full security as the sender does not provide a range proof that the transaction amount is less than its committed balance. That will be added in the next update. The trapdoor for the pedersen commitment is also sampled in the code and that will be removed later on. 

To run the code:
1. Install <code>pip install pqcrypto</code> for KEM and Signature
2. Install <code>pip install tinyec</code> for Elliptic curve operations
3. Install <code>pip install cryptography</code> for AES and SHA256 operations
4. Run <code>python3 confidential_txn_secpr1_curve.py</code>

THINGS TO DO:
1. Switch to Ristretto Curve
2. Add Bulletproofs to prove that the transaction amount is less than the sender's balance
3. Implement Hash_to_curve for H generation in Pedersen commitment
4. Provide Proof of Correct Decryption if transaction is invalid
5. Convert to Rust 
