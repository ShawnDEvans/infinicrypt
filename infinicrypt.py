#! /usr/bin/env python3
import hashlib
import bcrypt
import hashlib, binascii
import argparse 
import os

def get_md5(password):
    return hashlib.md5( password.encode('utf-8') ).hexdigest()

def get_ntlm(password):
    return hashlib.new('md4', password.encode('utf-16le')).hexdigest()

def get_sha1(password):
    return hashlib.sha1( password.encode('utf-8') ).hexdigest()

def get_3des(password, salt):
    pass

def get_sha512(password):
    return hashlib.sha512( password.encode('utf-8') ).hexdigest()

def get_bcrypt(password):
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt(12)) 

def get_sha256(password):
    return hashlib.sha256( password.encode('utf-8') ).hexdigest()

if __name__ == "__main__":
    
    parser = argparse.ArgumentParser(prog='infinicrypt', description='Infinicrypt - Multi format hash utility', epilog='Infinicrypt v1- Shawn Evans - sevans@nopsec.com')
    parser.add_argument('password', help='Single string or password file to be processed.')
    parser.add_argument('-b', '--bcrypt', help='Generate a bcrypt hash (random salt)', action='store_true')
    parser.add_argument('-m', '--md5', help='Generate MD5 hash', action='store_true')
    parser.add_argument('-n', '--ntlm', help='Generate NTLM hash',action='store_true')
    parser.add_argument('-s', '--sha1', help='Generate an SHA1 hash', action='store_true')
    parser.add_argument('--sha256', help='Generate an SHA256 hash', action='store_true')
    parser.add_argument('--sha512', help='Generate an SHA512 hash', action='store_true')
    args = parser.parse_args()
    
    passwords = [] 
    password = args.password  
    if os.path.isfile(password):
        passwords = [ line.rstrip('\n') for line in open(password) ]
    else:
        passwords.append( password.rstrip('\n') )

    for key in passwords:
        if args.bcrypt: print(get_bcrypt(key).decode('utf-8'))
        elif args.md5: print(get_md5(key))
        elif args.ntlm: print(get_ntlm(key))
        elif args.sha1: print(get_sha1(key))
        elif args.sha256: print(get_sha256(key))
        elif args.sha512: print(get_sha512(key))
        else: print('[!] Hash format not defined')
