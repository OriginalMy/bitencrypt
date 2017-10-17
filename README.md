# bitencrypt
bitencrypt is a Proof-of-Concept and a tutorial for encrypting messages using the private/public bitcoin key pair.

More information and tutorial on our blog post (in pt_BR): https://medium.com/@originalmy/bitencrypt-uma-prova-de-conceito-e-tutorial-para-criptografar-informações-usando-bitcoin-b757a7277265

TO DO:
- use pure ECDSA for signing the public key before sending. As ECDH has no authentication method, signing the public key at the moment of creation could help for preventing MITM attacks.
