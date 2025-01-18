import hashlib
import os
import threading
from concurrent.futures import ThreadPoolExecutor
import argparse

# New Banner
banner = r"""
 _  _   __   ____  _  _        ___  ____   __    ___  __ _  ____  ____ 
/ )( \ / _\ / ___)/ )( \ ___  / __)(  _ \ / _\  / __)(  / )(  __)(  _ \
) __ (/    \\___ \) __ ((___)( (__  )   //    \( (__  )  (  ) _)  )   /
\_)(_/\_/\_/(____/\_)(_/      \___)(__\_)\_/\_/ \___)(__\_)(____)(__\_)
                         
                           By Aysha Musthafa
"""

print(banner)

# Set up argument parsing
parser = argparse.ArgumentParser(description="Password Cracker")
parser.add_argument('-hash', required=True, help="Hash to crack")
parser.add_argument('-dict', required=True, help="Path to the dictionary file")
parser.add_argument('-algo', required=True, choices=['sha256', 'md5'], help="Hash algorithm to use")
args = parser.parse_args()

# Get values from arguments
hash_to_crack = args.hash.strip()
dictionary_path = args.dict
hash_algorithm = args.algo.strip().lower()

# Validate dictionary file
if not os.path.exists(dictionary_path) or not os.path.isfile(dictionary_path):
    print("Invalid dictionary file path.")
    exit()

class PasswordFound(Exception):
    pass

# Function to crack the hash
def crack_hash(password, algorithm):
    # Compute hash for md5 and sha256
    if algorithm == "sha256":
        computed_hash = hashlib.sha256(password.encode()).hexdigest()
    elif algorithm == "md5":
        computed_hash = hashlib.md5(password.encode()).hexdigest()
    
    # Check if the computed hash matches the hash to crack
    if computed_hash == hash_to_crack:
        raise PasswordFound(password)

def worker(password):
    try:
        crack_hash(password, hash_algorithm)
    except PasswordFound as e:
        print(f"Password found: {e}")
        stop_event.set()  # Signal to stop other threads

# Read passwords from dictionary
with open(dictionary_path, "r") as f:
    stop_event = threading.Event()
    passwords = [line.strip() for line in f]

    with ThreadPoolExecutor(max_workers=10) as executor:
        for password in passwords:
            if not stop_event.is_set():
                executor.submit(worker, password)

    if not stop_event.is_set():
        print("Password not found in the dictionary.")
