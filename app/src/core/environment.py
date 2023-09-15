from dotenv import load_dotenv
from os import getenv

load_dotenv()

def get(Name: str, type: str = 'str'):
    value = getenv(Name)
    match type:
        case 'str':
            return str(value)
        case 'int':
            return int(value)