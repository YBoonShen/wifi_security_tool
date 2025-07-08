import itertools
import string

def password_generator(min_length=6, max_length=None, charset=None):
    if charset is None:
        chars = string.printable.strip()
    else:
        chars = charset
    length = min_length
    while True:
        if max_length and length > max_length:
            break
        for p in itertools.product(chars, repeat=length):
            yield ''.join(p)
        length += 1