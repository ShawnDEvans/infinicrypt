# Infinicrypt
I needed to generate a bunch of hash files, and decided it would be useful to generate a tool for it. 

## Help
```
usage: infinicrypt [-h] [-b] [-m] [-n] [-s] [--sha256] [--sha512] password

Infinicrypt - Multi format hash utility

positional arguments:
  password      Single string or password file to be processed.

optional arguments:
  -h, --help    show this help message and exit
  -b, --bcrypt  Generate a bcrypt hash (random salt)
  -m, --md5     Generate MD5 hash
  -n, --ntlm    Generate NTLM hash
  -s, --sha1    Generate an SHA1 hash
  --sha256      Generate an SHA256 hash
  --sha512      Generate an SHA512 hash

Infinicrypt v1- Shawn Evans - sevans@nopsec.com
```

## Example
```
$ ./infinicrypt.py -b 'P@s$w0rd'
$2b$12$Q5kL6PbqJeKHLfkKHRsmlekaMn6015A2VqECaz4SkXZMEF7lPMJ7e
``` 
