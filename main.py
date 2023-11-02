# Python grub2-mkpasswd-pbkdf2 tool
# Written for Check Point CloudGuard images which require a grub2 format password hash
# for securing maintenance mode.
# This tool is for users who may not have access to a Linux machine with the necessary grub tools.
#
# Usage: python3 main.py
# (then enter your password, and copy the hash output)


import os # Needed for accessing pseudo random number generator
import sys # needed to exit with error code
from  hashlib import pbkdf2_hmac # Provides PBKDF2 hash functions
import logging # Logging the right way
from getpass import getpass # get the password and do not echo to screen

logging.basicConfig(format='%(levelname)s:%(message)s')

# Default values

# Use the system default pseudo random number generator which is suitable for crypto. Creating a 512b salt
salt = os.urandom(64) 

pbkdf2_iterations = 10000 # Default iterations used by grub2-mkpasswd-pbkdf2
sha_type = 'sha512' # sha256 is also a valid option

# Read password
password = getpass('Please enter your password: ')
password_conf = getpass('Please enter again to confirm: ')
# Check the user has typed it correctly
if password != password_conf:
  logging.error("Password and confirmation did not match")
  sys.exit(1)
else:
  dk = pbkdf2_hmac(sha_type, bytes(password, 'utf-8'), salt, pbkdf2_iterations)
  # Output the password in the same style as grub2-mkpasswd-pbkdf2
  print(f"grub.pbkdf2.{sha_type}.{pbkdf2_iterations}.{str(salt.hex()).upper()}.{str(dk.hex()).upper()}")
