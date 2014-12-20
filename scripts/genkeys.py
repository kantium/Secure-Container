#!/usr/local/bin/python3.4

# course:       ICR
# laboratory:   Practical Work #2 (Designing and Implementing a Secure Container for Medical Data)
# date:         26.11.2014
# author:       Stephane Kung
# description:  Generate 2 pairs of RSA keys (one pair for signature, one pair for encryption) 
# requirement:  Python3, PyCrypto 2.7a1

import sys

from Crypto.PublicKey import RSA 

#Write data to a file, default mode is binary
def write_to_file(filename,content,mode="wb"):
    with open(filename, mode) as outfile:
        outfile.write(content)

#Generate 2 pairs of RSA (private/public) keys of size 2048 by default
#Keys are created in the current directory
#Keys are named : enc_rsa, enc_rsa.pub, sign_rsa and sign_rsa.pub
def generate_RSA_keys(bits=2048):
    for n in ["sign","enc"]:
        priv_RSA_key = RSA.generate(bits)
        write_to_file("{0}_rsa".format(n),priv_RSA_key.exportKey("PEM"))
        write_to_file("{0}_rsa.pub".format(n),priv_RSA_key.publickey().exportKey("PEM"))

#Main code for generating RSA Keys
def main():
    #If no args are provided generate keys of default size
    if len(sys.argv) <= 1:
        generate_RSA_keys()
    else:
        generate_RSA_keys(int(sys.argv[1]))
    
    print("Keys generated")

if __name__ == "__main__":
    main()