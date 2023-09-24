from ..security.security import encodeToken, encodeTimeToken
from database.connections import UserDB, AuthCodesDB
from core.security.twofa import generateBackupCodes
from fastapi import Response, HTTPException
from datetime import datetime, timedelta
from .. import environment, comunicator
from config import auth as authConfig
import config as generalConfig
from datetime import datetime

def login_user(response: Response, userId: str) -> dict:
    expires = datetime.utcnow() + timedelta(hours= authConfig.Access_Token_Lifetime )

    access_token = encodeToken({
        "userId": userId,
        "type": "access",
        "issued": datetime.utcnow().timestamp(),
        "exp": expires
    })

    response.set_cookie(
        key="access_token",
        value=access_token,
        expires=expires.strftime('%a, %d-%b-%Y %T GMT')
    )

    return {
        'type': "access_token",
        'token_expires': expires.strftime("%m/%d/%Y %H:%M:%S")
    }


def generate_pending_account_token_response(userId: str, email: str, username: str, expires: datetime, service: dict = None) -> dict:
    token = encodeToken({
        "userId": userId,
        "type": "pending_account",
        "email": email,
        "username": username,
        "exp": expires,
        "service": service
    })

    return {
        "type": "pending_account",
        "token": token,
        "expires": expires.strftime("%m/%d/%Y %H:%M:%S")
    }


def generate_2a_token_response(userId: str, method: str):
    expires = datetime.utcnow() + timedelta(minutes=authConfig.Twofa_Token_Lifetime)

    token = encodeToken({
        "userId": userId,
        "type": "2fa",
        "issued": datetime.utcnow().timestamp(),
        "exp": expires
    })

    return {
        'type': "2fa_token",
        'token': token,
        'method': method,
        'token_expires': expires.strftime("%m/%d/%Y %H:%M:%S")
    }


def login_with_external_service(response: Response, serviceName: str, userId: str, email: str, username: str, profileImage: str) -> dict:
    connectedAccount = UserDB.find({"services": {'$elemMatch': {"name": serviceName, "id": userId} }})
    if(connectedAccount):
        if(connectedAccount.get('2fa', None) is None):
            return login_user(response, connectedAccount.get("_id"))
        else:
            return generate_2a_token_response(connectedAccount.get('_id'), connectedAccount.get('2fa').get('method'))
    

    account = UserDB.findUserByEmail(email)
    if(account):
       #TODO: add connect & login functionality 
       raise HTTPException(501, "Unable to connect and login to your account from external service")

    #Create account with service
    expires = datetime.utcnow() + timedelta(minutes=authConfig.Service_Account_Creation_Lifetime)

    token = encodeToken({
        "type": 'account_creation_with_serivce',
        "exp": expires,
        "serviceName": serviceName,
        "serviceUserId": userId,
        "serviceUsername": username,
        "email": email,
    })

    return {
        'type': 'account_creation_with_serivce',
        'token': token,
        'token_expires': expires.strftime("%m/%d/%Y %H:%M:%S")
    }

def connect_external_service(serviceName: str, serviceUserId: str, serviceUsername: str, user: str):
    if( checkIfServiceConnected(user, serviceName) ):
        raise HTTPException(400, f"{serviceName} is already connected")
    
    UserDB.update({"$push": {'services':{
        'name': serviceName,
        'id': serviceUserId,
        'username': serviceUsername
    }}}, id=user.get("_id"))

def getRedirectUri(path: str):
    return f"{generalConfig.Api_Uri}/{path}"

def checkIfServiceConnected(user: dict, name: str) -> bool:
    return next(iter(x for x in user.get('services') if x['name'] == name), None)


def send_password_reset_token(selector: str) -> None:
    account = UserDB.findUserBySelector(selector)
    if(not account):
        return

    if(AuthCodesDB.find({"type": "forgot-password", "userId": account.get("_id"), "type": "email"})):
        return

    token = encodeTimeToken({
        "type": "password_reset",
        "userId": account.get("_id"),
        "issued": datetime.utcnow().timestamp()
    }, Minutes=authConfig.Password_Reset_Token_Lifetime)

    #TODO: add front end client password reset uri 

    comunicator.send_email_template(
        "password_reset.html",
        account.get('email'),
        "Reset your password",
        username=account.get("username"),
        link=f"{generalConfig.Front_End_Uri}/resetpassword/{token}"
    )
    
    AuthCodesDB.insert({
        "type": "forgot-password",
        "userId": account.get("_id"),
        "expires": datetime.utcnow() + timedelta(minutes=authConfig.Password_Reset_Token_Lifetime),
    })

def fillBackupCodes(total: int, currentCodes: list[int], codeLenth: int = 12):
    genarateCount = total - len(currentCodes)
    if(genarateCount <= 0):
        return currentCodes[:total]

    return currentCodes + generateBackupCodes(genarateCount, codeLenth)
