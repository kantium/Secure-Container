#!/usr/local/bin/python3.4

# course:       ICR
# laboratory:   Practical Work #2 (Designing and Implementing a Secure Container for Medical Data)
# date:         26.11.2014
# author:       Stephane Kung
# description:  Unarchive an encrypted, authentified file and check is integrity
# requirement:  Python3, PyCrypto 2.7a1, a public signature key, a private encryption key

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

#Decrypt a ciphertext and test digest using GCM AES Mode.
#Raise an exception if digest doesn't match
def decrypt_GCM(key, nonce, ciphertext, digest):
    cipher = AES.new(key, AES.MODE_GCM, nonce)
    plaintext = cipher.decrypt(ciphertext)
    try:
        cipher.verify(digest)
    except:
        raise Exception("Key incorrect or message corrupted")
    return plaintext

#Decrypt a ciphertext using RSA
def decrypt(priv_enc_rsa_key, cipher):
    key = open(priv_enc_rsa_key, "r").read() 
    rsakey = RSA.importKey(key) 
    rsaenc = PKCS1_OAEP.new(rsakey) 
    return rsaenc.decrypt(cipher)

#Verify the integrity, and authentificate data using PKCS PSS signature
#Checksum on data a done with a SHA256 hashing function
#Raise an exception if signature doesn't match
def verify_sign(pub_sign_rsa_key, signature, data):
    pub_key = open(pub_sign_rsa_key, "r").read() 
    rsakey = RSA.importKey(pub_key) 
    signer = PKCS1_PSS.new(rsakey) 
    digest = SHA256.new() 
    digest.update(data) 
    if signer.verify(digest, signature):
        return True
    return False

#Write data to a file, default mode is binary
def write_to_file(filename,content,mode="wb"):
    with open(filename, mode) as outfile:
        outfile.write(content)

#Extract a tar file to the current directory
def extract(filename):
    tar = tarfile.open(filename)
    for tarinfo in tar:
        print("  file {0} extracted".format(tarinfo.name))
    tar.extractall()
    tar.close()

#Decrypt files provided as parameter
def decrypt_files(input_cipher, verify_key, decrypt_key):

    #Load the JSON file
    data = json.load(open(input_cipher))

    #test if content of JSON file is ok
    if len(data)!=5:
        raise Exception("Bad fileformat !")  

    #Recover all part of the JSON file in the corrects variables
    nonce,ciphertext,cipherdigest,signature,cipher_key = [b64_to_bytes(x) for x in data]

    #Verify the signature and raise an exception in case of missmatch
    if not (verify_sign(verify_key, signature, ciphertext)):
        raise Exception("Bad signature !")  

    #Decrypt the symetric key unsing the private encryption RSA key
    key = decrypt(decrypt_key, cipher_key)

    #Decrypt the ciphertext with the symetric key and check the integrity of data (as part of GCM Mode)
    plaintext = decrypt_GCM(key, nonce, ciphertext, cipherdigest) 
    
    #Create the tar file with plain data, extract content file and delete the tar file.
    temp_tarfile = "{0}.tar".format(input_cipher)
    open(temp_tarfile, 'wb').write(plaintext)
    extract(temp_tarfile)
    os.remove(temp_tarfile) 

#Main code for decrypting a list of files provided as parameter
def main():
    #Test if at least one file is provided as parameter
    if len(sys.argv) <= 1:
        print("Usage : {0} [encrypted_files...]".format(str(sys.argv[0])))
        exit(1)
    #Test if all files provided in parameter exists
    elif [x for x in sys.argv[1:] if not os.path.isfile(x)]:
        print("at least one file does not exist !")
        exit(2)

    #for each encrypted file provided in parameter
    for encrypted_file in sys.argv[1:]:
        try:
            print("Decrypting {0}...".format(encrypted_file))
            #Try to decrypt the file, using the public signature and private encryption key
            decrypt_files(encrypted_file, "sign_rsa.pub", "enc_rsa")
        except Exception as e:
            print("  Unable to decrypt {0} ({1})".format(encrypted_file,e.args[0]))

if __name__ == "__main__":
    main()