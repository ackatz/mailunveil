import re
import math
from collections import Counter
from itertools import groupby


# Helper function: Calculate the entropy of a string
def entropy_of_string(s):
    p, l = Counter(s), float(len(s))
    return -sum(count / l * math.log2(count / l) for count in p.values())


# Helper function: Check for long sequences of consecutive characters (either digits or letters)
def has_consecutive_sequences(s, threshold=5):
    return any(len(list(group)) >= threshold for _, group in groupby(s))


# Helper function: Check for excessive digit use in the string
def has_too_many_digits(s, digit_ratio=0.3):
    return sum(c.isdigit() for c in s) / len(s) > digit_ratio


# The main function to check if an email is suspiciously random
async def check(email, entropy_threshold=4, digit_ratio=0.3, sequence_threshold=5):
    try:
        local, domain = email.split("@")
    except ValueError:
        # If the email doesn't split into exactly two parts, it's invalid
        return False

    # Check if the local part has high entropy
    if entropy_of_string(local) > entropy_threshold:
        return True

    # Check for long sequences of consecutive digits or letters
    if has_consecutive_sequences(local, sequence_threshold):
        return True

    # Check if the local part is alphanumeric and has a high ratio of digits
    if local.isalnum() and has_too_many_digits(local, digit_ratio):
        return True

    # If none of the checks indicate randomness, return False
    return False
