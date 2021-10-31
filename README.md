# Crypto-project
# ADVANCED ENCRYPTION STANDARD
The Advanced Encryption Standard (AES) is a symmetric block cipher chosen by 
the U.S. government to protect classified information. AES is implemented in 
software and hardware throughout the world to encrypt sensitive data. It is 
essential for government computer security, cybersecurity and electronic data 
protection
# Features of AES:
• Block encryption implementation 
• 128-bit group encryption with 128,192 and 256-bit key lengths
• Symmetric algorithm requiring only one encryption and decryption key
• Data security for 20-30 years
• Worldwide access
• No royalties
• Easy overall implementation 
# Process of AES:
Initial round key addition
ADD round key-each byte of the state is combined with a byte of the round 
key using bitwise xor

• SUB BYTES: a non-linear substitution step where each byte is replaced with 
another according to a lookup table

• Shift-rows: a transposition step where the last three rows of the state are 
shifted cyclically certain number of steps

• Mix columns- a linear mixing operation which operates on the columns of 
the state combining the four bytes in each column which is done by Galois 
multiplication.

• Key expansion: Round keys are derived from the cipher key using the AES 
key schedule. AES requires a separate 128-bit round key block for each 
round plus one more

Steps involved in Key expansion:

1.One-byte circular left shift

2. byte substitution using forward S-box

3.XOR with Round constant
Keying restrictions:

No weak or semi-weak keys have been identified for AES algorithm and there is 

no restriction for key selection. 


