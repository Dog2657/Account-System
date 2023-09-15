from dataclasses import dataclass, field, asdict

def asDict(data: dataclass) -> dict:
    return asdict(data)

@dataclass
class User:
    username: str
    email: str
    passwordHash: str
    services: list = field(default_factory=list)
    #phone: dict = field(default_factory= lambda: {
    #    'number': str,
    #    'verified': bool,
    #})

@dataclass
class PendingUser:
    email: str
    expires: str
    username: str
    passwordHash: str
    service: dict = field(default_factory= lambda: {
        'name': str,
        'id': int,
    })