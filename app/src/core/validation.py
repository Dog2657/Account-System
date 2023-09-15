from email_validator import validate_email, EmailNotValidError
import phonenumbers

def email(address: str) -> bool:
    try:
        validate_email(address)
        return True
    except EmailNotValidError as e:
        return False
    
def phone_number(number: str) -> bool:
    parsed = phonenumbers.parse(number)
    return phonenumbers.is_possible_number(parsed)

def password(value: str) -> bool:
    #TODO: add password checks
    return True