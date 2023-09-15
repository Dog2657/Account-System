from database.connections import UserDB, PendingUserDB, invalidAccessTokensDB
from ..security.security import decodeToken
from fastapi import HTTPException, Cookie
from datetime import datetime
from typing import Annotated
import jose 

def decode_Token(token: str, type: str):
    try:
        token = decodeToken(token)
        if(token.get("type", None) != type):
            raise HTTPException(301, "Invalid token type")
        
        return token

    except jose.ExpiredSignatureError as _:
        raise HTTPException(301, "Token expired")
    
    except jose.JWTError as _:
        raise HTTPException(300, "Token error")

    except jose.jwt.JWTClaimsError as _:
       raise HTTPException(300, "Token error")
    

def getUserFrom2faAuthToken(token: str):
    token = decode_Token(token, "2fa")
    
    result = UserDB.find(id=token.get('userId', ''))
    if(result is None):
        raise HTTPException(300, "No account connected to this token")
    
    issuedToken = datetime.fromtimestamp(token.get("issued"))
    if(issuedToken < result.get('lastPasswordChange', issuedToken)):
        raise HTTPException(401, "2fa token invalidated due to recent password change")
    
    if(result.get('2fa', None) is None):
        raise HTTPException(400, "Thisccount dosen't have 2fa enabled")

    return result

def getUserFromActivationToken(token: str):
    token = decode_Token(token, "pending_account")

    result = PendingUserDB.find({'email': token.get("email", ""), "username": token.get("username", '')}, id=token.get('userId', ''))
    if( not result ):
        raise HTTPException(401, "Invalid activation token")
    
    return result


def getUserFromAccessToken(access_token: Annotated[str | None, Cookie()] = None):
    if(access_token is None):
        raise HTTPException(401, "This endpoint requires being logged in to use")
    
    token = decode_Token(access_token, "access")

    if(invalidAccessTokensDB.find({"token": access_token})):
        raise HTTPException(401, "This access token has been logged out")

    account = UserDB.find(id=token.get("userId"))
    if(account is None):
        raise HTTPException(404, "Unable to get user details at the moment")
    
    issuedToken = datetime.fromtimestamp(token.get("issued"))
    if(issuedToken < account.get('lastPasswordChange', issuedToken)):
        raise HTTPException(401, "Access token invalidated due to recent password change")
    
    return account 

def notLoggedIn(access_token: Annotated[str | None, Cookie()] = None):
    if(access_token is not None):
        raise HTTPException(401, "You are already logged in")