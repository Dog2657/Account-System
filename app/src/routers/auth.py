from fastapi import APIRouter, Form, HTTPException, Response, Depends, BackgroundTasks
from core.security.security import verify_password, generateOneTimeCode, hash_password
from database.connections import UserDB, AuthCodesDB, PendingUserDB
from config import email as emailConfig, phone as phoneConfig
from core.auth import auth, dependencies as authDependencies
from core.security.twofa import getTimeOTP
from core import validation as validate
from datetime import datetime, timedelta
from typing import Annotated
from core import comunicator

router = APIRouter(dependencies=[ Depends(authDependencies.notLoggedIn) ])

@router.post("/login", tags=['Login'])
async def POST_Login(selector: Annotated[str, Form()], password: Annotated[str, Form()], response: Response):
    result = UserDB.findUserByEmail(selector) if (validate.email(selector)) else UserDB.findUserByUsername(selector)
    if(result is None):
        pendingResult = PendingUserDB.find({'$or': [ {"email": selector.lower()}, {"username": {'$regex': f'^{selector}$', "$options": 'i'} } ]})
        if( pendingResult ):
            if(not verify_password(password, pendingResult.get('passwordHash'))):
                raise HTTPException(401, "Password is incorect")
            else:
                return auth.generate_pending_account_token_response( pendingResult.get("_id"), pendingResult.get('email'), pendingResult.get('username'), pendingResult.get('expires') )
            
        del pendingResult
        raise HTTPException(404, "No account with that email/username")
    
    
    if(not verify_password(password, result.get('passwordHash'))):
        raise HTTPException(401, "Password is incorect")
    
    if(result.get('2fa', None) is None):
        return auth.login_user(response, result.get('_id'))
    
    return auth.generate_2a_token_response(result.get('_id'), result['2fa']['method'])


@router.put('/resend-2fa-code', tags=["2fa login"])
async def PUT_Resend_2fa_Code(user = Depends(authDependencies.getUserFrom2faAuthToken)):
    search = AuthCodesDB.find({"userId": user.get("_id"), "type": "auth", "method": user.get('2fa').get('method')})
    if(search):
        if( search.get('expires') <= datetime.utcnow()):
            AuthCodesDB.delete(id=search.get('_id'))
        else:
            raise HTTPException(401, f"Still on cooldown till ({search.get('expires')})")
        

    code = generateOneTimeCode()
    delta: timedelta

    match user.get('2fa').get('method'):
        case 'email':
            delta = emailConfig.Email_Auth_Codes_Lifetime
            try:
                comunicator.send_email_template(
                    templateName='2fa_login.html',
                    to=user.get('email', None),
                    subject="Your 2fa login code",
                    code=code
                )
            except Exception as error:
                raise HTTPException(500, "Unable to send email")
            
        case "phone":
            delta = phoneConfig.Phone_2fa_Auth_Code_Lifetime
            try:
                comunicator.send_sms_template(
                    templateName='2fa_login.txt',
                    to=user.get("phone"),
                    code=code
                )
            except Exception as error:
                raise HTTPException(500, "Unable to send text message")
            
        case _:
            raise HTTPException(400, "Account 2fa method dosen't require a code to be sent")
    
    

    AuthCodesDB.insert({
        "code": code,
        "userId": user.get('_id'),
        "method": user.get('2fa').get('method'),
        "type": "auth",
        "expires": datetime.utcnow() + delta
    })


@router.post('/login-with-2fa-code', tags=["2fa login"])
async def POST_Login_With_2fa_Code(response: Response, code: Annotated[str, Form()], user = Depends(authDependencies.getUserFrom2faAuthToken)):
    match user.get('2fa').get('method'):
        case 'email' | 'phone':
            search = AuthCodesDB.find({"userId": user.get("_id"), "type": "auth", "method": user.get('2fa').get('method'), "type": "auth"})
            if(search is None):
                raise HTTPException(404, 'Unable to find an active code')
            
            if(search.get('expires') <= datetime.utcnow()):
                AuthCodesDB.delete(id=search.get('_id'))
                raise HTTPException(401, 'Code has expired')

            if(search.get('code') != code.upper()):
                raise HTTPException(401, "Code is incorrect")
            
            AuthCodesDB.delete(id=search.get('_id'))
            
        case 'authenticator':
            if( str( getTimeOTP( user.get('2fa').get("secret") ) ) != code):
                raise HTTPException(401, "Code is incorrect")


    return auth.login_user(response, user.get('_id'))


@router.post('/Disable-2fa-with-backup-code', tags=["2fa login"])
async def POST_Disable_2fa_With_Backup_Code(response: Response, code: Annotated[int, Form()], user = Depends(authDependencies.getUserFrom2faAuthToken)):
    codes: list[int] = user.get('backup-codes')

    if(code not in codes):
        raise HTTPException(401, 'Invalid code')
    
    UserDB.update({"$pull": {"backup-codes": code}, "$unset": {'2fa': 1}}, id=user.get("_id"))

    return auth.login_user(response, user.get('_id'))



@router.post("/forgot-password", tags=["Reset Password"])
async def POST_Reset_Password(selector: Annotated[str, Form()], background_tasks: BackgroundTasks):
    background_tasks.add_task(auth.send_password_reset_token, selector)


@router.put('/forgot-password/{token}', tags=["Reset Password"])
async def PUT_Set_Reset_Password(token: str, password: Annotated[str, Form()]):
    details = authDependencies.decode_Token(token, "password_reset")

    account = UserDB.find(id=details.get("userId"))
    if(not account):
        raise HTTPException(404, "The account linked to this token cant be found")

    issuedToken = datetime.fromtimestamp(details.get("issued"))
    if(issuedToken < account.get('lastPasswordChange', issuedToken)):
        raise HTTPException(401, "Token invalidated due to recent password change")
    
    if(verify_password(password, account.get("passwordHash"))):
        raise HTTPException(400, "Password can't be the same")

    if(not validate.password(password)):
        raise HTTPException(400, "Password is week")
    
    UserDB.update({"$set": {
        "passwordHash": hash_password(password),
        "lastPasswordChange": datetime.utcnow()
    }}, id=account.get("_id"))