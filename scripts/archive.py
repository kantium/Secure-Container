#!/usr/local/bin/python3.4

# course:       ICR
# laboratory:   Practical Work #2 (Designing and Implementing a Secure Container for Medical Data)
# date:         26.11.2014
# author:       Stephane Kung
# description:  Securely archive files using encryption, authentification and integrity. 
# requirement:  Python3, PyCrypto 2.7a1, a private signature key, a public encryption key

import os
import sys
import json
import tarfile

from time import gmtime, strftime
from base64 import b64encode, b64decode 
from binascii import hexlify
from Crypto.Hash import SHA256 
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA 
from Crypto.Signature import PKCS1_PSS

#Convert bytes to a string
def bytes_to_string(b):
    return str(hexlify(b),'ascii')

#Convert bytes to a base 64 string
def bytes_to_b64(b):
    return str(b64encode(b),'ascii')

#Convert a base 64 string to bytes
def b64_to_bytes(b64):
    return b64decode(b64)

#Encrypt a plaintext using GCM AES Mode 
#(which require a nonce and symetric key)
def encrypt_GCM(key, nonce, plaintext):
    cipher = AES.new(key, AES.MODE_GCM, nonce)
    return cipher.encrypt(plaintext),cipher.digest()

#Encrypt a plaintext using RSA asymetric algorithm.
def encrypt(pub_enc_rsa_key, plaintext):
    key = open(pub_enc_rsa_key, "r").read()
    rsakey = RSA.importKey(key)
    rsaenc = PKCS1_OAEP.new(rsakey)
    return rsaenc.encrypt(plaintext)

#Create a signature for byte content using PKCS PSS on
# a SHA256 digest of entire data
def sign_data(priv_sign_rsa_key, data):
    key = open(priv_sign_rsa_key, "r").read() 
    rsakey = RSA.importKey(key) 
    signer = PKCS1_PSS.new(rsakey) 
    digest = SHA256.new() 
    digest.update(data) 
    return signer.sign(digest) 

#Write data to a file, default mode is binary
def write_to_file(filename,content,mode="wb"):
    with open(filename, mode) as outfile:
        outfile.write(content)

#Encrypt files provided as parameter to an output secure archive
def encrypt_files(output_cipher, files_to_encrypt, sign_key, encrypt_key):

    #Create a Tar file
    temp_tarfile = "{0}.tar".format(output_cipher)
    with tarfile.open(temp_tarfile, "w") as tar:
        for filename in files_to_encrypt:
            tar.add(filename)

    #Read the temporary tar file created
    bytes_read = open(temp_tarfile, "rb").read()
    
    #Create Cryptographic parameters
    key = get_random_bytes(32)
    nonce = get_random_bytes(11)
    
    #Encrypt tar file content with GCM MODE and get cipher and digest
    ciphertext,cipherdigest = encrypt_GCM(key, nonce, bytes_read)
    
    #Sign ciphertext part
    signature = sign_data(sign_key, ciphertext)
    
    #Encrypt symetric encryption key
    cipher_key = encrypt(encrypt_key, key)

    #Create the contener as a tuple
    cipher_contener = [bytes_to_b64(x) for x in (nonce, ciphertext, cipherdigest, signature, cipher_key)]

    #Write the encrypted contener to a file and delete the temporary tar file
    write_to_file(output_cipher,json.dumps(cipher_contener),"wt")
    os.remove(temp_tarfile) 

#Main code for encrypting a list of files provided as parameter to an archive file
def main():
    #Test if a least a file is provided
    if len(sys.argv) <= 1:
        print("Usage : {0} [secret_files...]\n".format(str(sys.argv[0])))
        exit(1)

    #Test if all files provided exists
    elif [x for x in sys.argv[1:] if not os.path.isfile(x)]:
        print("at least one file does not exist !")
        exit(2)
    
    #Create a name for the secure archive
    cipher_file = "{0}.enc".format(strftime("%Y%m%d%H%M%S", gmtime()))

    #Encrypt files to the secure archive
    encrypt_files(cipher_file, sys.argv[1:], "sign_rsa", "enc_rsa.pub")

if __name__ == "__main__":
    main()