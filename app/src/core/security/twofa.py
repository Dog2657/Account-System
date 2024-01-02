from .security import generateOneTimeNumberCode
import config as generalConfig
import pyotp

def generateBackupCodes(quantity: int = 10, codeLength: int = 12) -> list[int]:
    return [ generateOneTimeNumberCode(codeLength) for _ in range(quantity) ]

def generateSecretKey(length = 32) -> str:
    return pyotp.random_base32(length)

def getTimeOTP(Key: str) -> int:
    totp = pyotp.TOTP(Key)
    return int(totp.now())

def getCountOTP(Key: str, Location: int) -> int:
    hotp = pyotp.HOTP(Key)
    return int(hotp.at(Location))

def get_2FA_URI(Key: str, Name: str) -> str:
    return pyotp.totp.TOTP(Key).provisioning_uri(name=Name, issuer_name=generalConfig.Issuer )