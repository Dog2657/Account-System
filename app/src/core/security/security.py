from passlib.context import CryptContext
from datetime import datetime, timedelta
from .. import environment
from jose import jwt
import random
import string

Token_Signing_Key = environment.get("Token_Signing_Key")
Token_Algorithm = environment.get("Token_Algorithm")
Password_Context = CryptContext(schemes=["bcrypt"], deprecated="auto")

#Password functions
def hash_password(plain_pwd: str) -> str:
    return Password_Context.hash(plain_pwd)

def verify_password(plain_pwd: str, hashed_pwd: str) -> bool:
    return Password_Context.verify(plain_pwd, hashed_pwd)


#Token functions
def encodeToken(data: dict) -> str:
    return jwt.encode(data, Token_Signing_Key, algorithm=Token_Algorithm)

def decodeToken(token: str) -> str:
    return jwt.decode(token, Token_Signing_Key, Token_Algorithm)
   
def encodeTimeToken( data: dict, diffrence: timedelta ) -> str:
    encode = data.copy()
    encode['exp'] = datetime.now() + diffrence
    return encodeToken(encode)


#Code Generation
def generateOneTimeCode(Length: int = 6) -> str:
    Code: str = ""
    for _ in range(0, Length):
        if random.random() > 0.5:
            Code += str( random.randint(0,9) )
        else:
            Code += random.choice(string.ascii_uppercase)
    return Code

def generateOneTimeNumberCode(Length: int = 6) -> int:
    return int(''.join([str(random.randint(0,9)) for i in range(6)]))