import hashlib
from passlib.hash import bcrypt

# VULNERÁVEL: Hash MD5 (não recomendado)
def hash_md5(password: str) -> str:
    return hashlib.md5(password.encode()).hexdigest()

# SEGURO: Hash bcrypt
def hash_bcrypt(password: str) -> str:
    return bcrypt.hash(password)

def verify_bcrypt(password: str, hashed: str) -> bool:
    return bcrypt.verify(password, hashed)
