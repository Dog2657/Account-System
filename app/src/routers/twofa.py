from core.security.twofa import generateSecretKey, getTimeOTP, generateBackupCodes
from core.security.security import encodeToken, decodeToken, generateOneTimeCode
from core.auth.dependencies import getUserFromAccessToken, decode_Token
from fastapi import APIRouter, Depends, Form, HTTPException
from core.auth.auth import fillBackupCodes
from datetime import datetime, timedelta
from database.connections import UserDB, AuthCodesDB
from core import environment, comunicator
from typing import Annotated
from config import auth as authConfig, email as emailConfig, phone as phoneConfig

router = APIRouter(prefix="/2fa")

@router.post('-activation/authenticator', tags=["Start Activate 2fa"])
async def POST_Start_Activation_Time(user = Depends(getUserFromAccessToken)):
    if(user.get("2fa")):
        raise HTTPException(401, "You already have 2fa enabled")
    
    expires = datetime.utcnow() + timedelta(hours=authConfig.Time_2fa_Activation_Token_Lifetime)
    secret = generateSecretKey()

    token = encodeToken({
        "userId": user.get("_id"),
        "type": "2fa_Authenticator_Activation",
        "exp": expires,
        "secret": secret
    })

    return {
        'type': "2fa_Authenticator_Activation",
        'token': token,
        "secret": secret,
        'token_expires': expires.strftime("%m/%d/%Y %H:%M:%S")
    }


@router.put('-activate/authenticator/{token}', tags=["Finish Activate 2fa"])
async def PUT_Finish_Activation_Time(token: str, code: Annotated[int, Form()], user = Depends(getUserFromAccessToken)):
    details = decode_Token(token, "2fa_Authenticator_Activation")

    if(details.get("userId") != user.get("_id")):
        raise HTTPException(401, "This token is for another user")
    
    if(user.get("2fa")):
        raise HTTPException(401, "You already have 2fa enabled")

    if(getTimeOTP(details.get("secret")) != code):
        raise HTTPException(401, "Code is invalid")
    
    backupCodes = fillBackupCodes(10, user.get('backup-codes', generateBackupCodes()) )

    UserDB.update({"$set": {
        "backup-codes": backupCodes,
        "2fa": {
            "method": "authenticator",
            "secret": details.get("secret")
        }
    }})

    return { "backup-codes": backupCodes }




@router.post('-activate/email', tags=["Start Activate 2fa"])
async def POST_Start_Activation_Email(user = Depends(getUserFromAccessToken)):
    if(user.get("2fa")):
        raise HTTPException(401, "You already have 2fa enabled")
    
    expires = datetime.utcnow() + timedelta(minutes=emailConfig.Email_2fa_Activation_Token_Lifetime)  

    token = encodeToken({
        "userId": user.get("_id"),
        "type": "2fa_Email_Activation",
        "exp": expires,
    })

    return {
        'type': "2fa_Email_Activation",
        'token': token,
        'token_expires': expires.strftime("%m/%d/%Y %H:%M:%S")
    }

@router.put('-activate/email/{token}', tags=["Finish Activate 2fa"])
async def PUT_Finish_Activation_Email(token: str, code: Annotated[str, Form()], user = Depends(getUserFromAccessToken)):
    tokenDetails = decode_Token(token, "2fa_Email_Activation")

    if(tokenDetails.get("userId") != user.get("_id")):
        raise HTTPException(401, "This token is for another user")

    if(user.get("2fa")):
        raise HTTPException(401, "You already have 2fa enabled")

    search = AuthCodesDB.find({"userId": user.get("_id"), "type": "activate_2fa", "method": "email"})
    if(not search):
        raise HTTPException(401, "No active codes found")
    
    if( search.get('expires') <= datetime.utcnow()):
        AuthCodesDB.delete(id=search.get('_id'))
        raise HTTPException(401, "No active codes found")
    
    if(search.get('code') != code):
        raise HTTPException(401, "Code is invalid")
    
    backupCodes = fillBackupCodes(10, user.get('backup-codes', generateBackupCodes()) )

    UserDB.update({"$set": {
        "backup-codes": backupCodes,
        "2fa": {
            "method": "email",
        }
    }})

    AuthCodesDB.delete(id=search.get('_id'))
    return { "backup-codes": backupCodes }
    


@router.post('-activate/phone', tags=["Start Activate 2fa"])
async def POST_Start_Activation_Phone(user = Depends(getUserFromAccessToken)):
    if(user.get("2fa")):
        raise HTTPException(401, "You already have 2fa enabled")
    
    if(user.get('phone') is None):
        raise HTTPException(400, "No phone number linked with this account")
    
    expires = datetime.utcnow() + timedelta(minutes=phoneConfig.Phone_2fa_Activation_Token_Lifetime)  

    token = encodeToken({
        "userId": user.get("_id"),
        "type": "2fa_Phone_Activation",
        "exp": expires,
    })

    return {
        'type': "2fa_Phone_Activation",
        'token': token,
        'token_expires': expires.strftime("%m/%d/%Y %H:%M:%S")
    }


@router.put('-activate/phone/{token}', tags=["Finish Activate 2fa"])
async def PUT_Finish_Activation_Phone(token: str, code: Annotated[str, Form()], user = Depends(getUserFromAccessToken)):
    tokenDetails = decode_Token(token, "2fa_Phone_Activation")

    if(tokenDetails.get("userId") != user.get("_id")):
        raise HTTPException(401, "This token is for another user")

    if(user.get("2fa")):
        raise HTTPException(401, "You already have 2fa enabled")

    search = AuthCodesDB.find({"userId": user.get("_id"), "type": "activate_2fa", "method": "phone"})
    if(not search):
        raise HTTPException(401, "No active codes found")
    
    if( search.get('expires') <= datetime.utcnow()):
        AuthCodesDB.delete(id=search.get('_id'))
        raise HTTPException(401, "No active codes found")
    
    if(search.get('code') != code):
        raise HTTPException(401, "Code is invalid")
    
    backupCodes = fillBackupCodes(10, user.get('backup-codes', generateBackupCodes()) )

    UserDB.update({"$set": {
        "backup-codes": backupCodes,
        "2fa": {
            "method": "phone",
        }
    }})

    AuthCodesDB.delete(id=search.get('_id'))
    return { "backup-codes": backupCodes }





@router.put('/resend-activation-code', tags=["Send 2fa state update codes"])
async def PUT_Resend_2fa_Code(tokenDetails = Depends(decodeToken), user = Depends(getUserFromAccessToken)):
    activationType = None
    match tokenDetails.get("type"):
        case "2fa_Email_Activation": 
            activationType = "email"

        case "2fa_Phone_Activation":
            activationType = "phone"

        case _:
            raise HTTPException(401, "Invalid token")


    if(tokenDetails.get("userId") != user.get("_id")):
        raise HTTPException(401, "This token is for another user")

    if(user.get("2fa")):
        raise HTTPException(401, "You already have 2fa enabled")


    search = AuthCodesDB.find({"userId": user.get("_id"), "type": "activate_2fa", "method": activationType})
    if(search):
        if( search.get('expires') <= datetime.utcnow()):
            AuthCodesDB.delete(id=search.get('_id'))
        else:
            raise HTTPException(401, f"Still on cooldown till ({search.get('expires')})")
        
    
    code = generateOneTimeCode()
    delta: timedelta

    match activationType:
        case 'email':
            delta = timedelta(minutes=emailConfig.Email_2fa_Activation_Token_Lifetime)
            try:
                comunicator.send_email_template(
                    templateName='2fa_activation.html',
                    to=user.get('email', None),
                    subject="Activate 2fa on your account",
                    code=code
                )
            except Exception as error:
                raise HTTPException(500, "Unable to send email")
      
        case "phone":
            delta = timedelta(minutes=phoneConfig.Phone_2fa_Activation_Token_Lifetime)
            try:
                comunicator.send_sms_template(
                    templateName='2fa_activation.txt',
                    to=user.get("phone", None),
                    code=code
                )
            except Exception as error:
                raise HTTPException(500, "Unable to send text message")

        case _:
            raise HTTPException(400, "Account 2fa method dosen't require a code to be sent")
    
    AuthCodesDB.insert({
        "userId": user.get("_id"),
        "type": "activate_2fa",
        "method": activationType,
        "code": code,
        "expires": datetime.utcnow() + delta
    })



@router.put('/send-deactivating-code', tags=["Deactivate 2fa"])
async def PUT_Send_Deactivation_Code(user = Depends(getUserFromAccessToken)):
    if(user.get("2fa") is None):
        raise HTTPException(400, "This account dosen't have 2fa enabled")
    
    if(user.get('2fa').get('method') not in ['email', 'phone']):
        raise HTTPException(400, "The 2fa method dosen't require sending a code")
    
    search = AuthCodesDB.find({"userId": user.get("_id"), "type": "deactivate_2fa", "method": user.get('2fa').get('method')})
    if(search):
        if( search.get('expires') <= datetime.utcnow()):
            AuthCodesDB.delete(id=search.get('_id'))
        else:
            raise HTTPException(401, f"Still on cooldown till ({search.get('expires')})")
        
    code = generateOneTimeCode()
    delta: timedelta

    match user.get('2fa').get('method'):
        case 'email':
            delta = timedelta(minutes=emailConfig.Email_2fa_Deactivation_Token)
            try:
                comunicator.send_email_template(
                    templateName='2fa_deactivation.html',
                    to=user.get('email', None),
                    subject="Deactivate 2fa on your account",
                    code=code
                )
            except Exception as error:
                raise HTTPException(500, "Unable to send email")
      
        case "phone":
            delta = timedelta(minutes=phoneConfig.Phone_2fa_Deactivation_Token)
            try:
                comunicator.send_sms_template(
                    templateName='2fa_deactivation.txt',
                    to=user.get("phone", None),
                    code=code
                )
            except Exception as error:
                raise HTTPException(500, "Unable to send text message")

        case _:
            raise HTTPException(400, "Account 2fa method dosen't require a code to be sent")
    
    AuthCodesDB.insert({
        "userId": user.get("_id"),
        "type": "deactivate_2fa",
        "method": user.get('2fa').get('method'),
        "code": code,
        "expires": datetime.utcnow() + delta
    })

@router.post('/deactivating', tags=["Deactivate 2fa"])
async def POST_Deactivate_2fa(code: Annotated[str, Form()], user = Depends(getUserFromAccessToken)):
    if(user.get("2fa") is None):
        raise HTTPException(400, "This account dosen't have 2fa enabled")
    
    
    match user.get('2fa').get('method'):
        case 'email' | 'phone':
            search = AuthCodesDB.find({"userId": user.get("_id"), "type": "deactivate_2fa", "method": user.get('2fa').get('method')})
            if(not search):
                raise HTTPException(401, "No active codes found")
            
            if( search.get('expires') <= datetime.utcnow()):
                AuthCodesDB.delete(id=search.get('_id'))
                raise HTTPException(401, "No active codes found")
            
            if(search.get('code') != code):
                raise HTTPException(401, "Code is invalid")
            
            AuthCodesDB.delete(id=search.get("_id"))
            
        case 'authenticator':
            if( str( getTimeOTP( user.get('2fa').get("secret") ) ) != code):
                raise HTTPException(401, "Code is incorrect")
    
    UserDB.update({"$unset": {"2fa": 1}}, id=user.get("_id"))