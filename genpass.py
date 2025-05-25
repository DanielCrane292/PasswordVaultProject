# genpass.py
# Author: Daniel
# Student Number: 123456789
# GitHub Username: yourGitHubUsername

import random
import string

def generate_password(length=12, use_lower=True, use_upper=True, use_digits=True, use_symbols=True):
    chars = ''
    if use_lower:
        chars += string.ascii_lowercase
    if use_upper:
        chars += string.ascii_uppercase
    if use_digits:
        chars += string.digits
    if use_symbols:
        chars += string.punctuation

    if not chars:
        raise ValueError("At least one character type must be selected.")

    return ''.join(random.choice(chars) for _ in range(length))

# Test code
if __name__ == "__main__":
    print(generate_password(12, True, True, True, True))
