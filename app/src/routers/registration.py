from core.auth.auth import generate_pending_account_token_response, login_user
from core.auth.dependencies import decode_Token, getUserFromActivationToken
from core.security.security import hash_password, generateOneTimeCode
from fastapi import APIRouter, HTTPException, Depends, Response, Form
from database.connections import UserDB, PendingUserDB, AuthCodesDB
from core import environment, validation as validate
from database.models import User, PendingUser
from datetime import datetime, timedelta
from dataclasses import asdict
from typing import Annotated
from config import auth as authConfig
from core import comunicator

router = APIRouter()

@router.post('/signup', tags=['Signup'])
async def POST_Signup(email: Annotated[str, Form()], username: Annotated[str, Form()], password: Annotated[str, Form()]):
    if( UserDB.find({'$or': [ {"email.address": email.lower()}, {"username": {'$regex': f'^{username}$', "$options": 'i'} } ]}) ):
        raise HTTPException(400, "Email and or Username is already taken")

    if( PendingUserDB.find({'$or': [ {"email": email.lower()}, {"username": {'$regex': f'^{username}$', "$options": 'i'} } ]}) ):
        raise HTTPException(400, "Account already made and awaiting activation")

    if(not validate.email(email)):
        raise HTTPException(401, "Invalid email address")
    
    if(not validate.password(password)):
        raise HTTPException(400, "Password is week")
    
    expires = datetime.utcnow() + timedelta(hours=authConfig.Pending_Accounts_Lifetime_Token)

    id = PendingUserDB.insert(asdict( PendingUser(email, expires, username, hash_password(password), None) ))

    return generate_pending_account_token_response(id, email, username, expires)




@router.patch("/activate-account", tags=['Signup verification'])
async def PATCH_Activate_Account(response: Response, code: Annotated[str, Form()], user = Depends(getUserFromActivationToken)):
    search = AuthCodesDB.find({"userId": user.get("_id"), "method": 'email', "type": "activation"})
    if(search is None):
        raise HTTPException(404, 'Unable to find an active code')
    
    if(search.get('expires') <= datetime.utcnow()):
        AuthCodesDB.delete(id=search.get('_id'))
        raise HTTPException(401, 'Code has expired')

    if(search.get('code') != code.upper()):
        raise HTTPException(401, "Code is incorrect")
    
    AuthCodesDB.delete(id=search.get('_id'))
    PendingUserDB.delete(id=user.get('userId'))


    account = User(user.get("username"), user.get("email"), user.get('passwordHash'))
    if(user.get('service', None)):
        account.services = [user.get('service')]

    userId = UserDB.insert(asdict(account))

    return login_user(response, userId)



@router.put("/resend-activation-code", tags=['Signup verification'])
async def PUT_resend_activation_Code(user = Depends(getUserFromActivationToken)):
    search = AuthCodesDB.find({"userId": user.get("_id"), "method": "email", "type": "activation"})
    if(search):
        if( search.get('expires') <= datetime.utcnow()):
            AuthCodesDB.delete(id=search.get('_id'))
        else:
            raise HTTPException(401, f"Still on cooldown till ({search.get('expires')})")
        

    code = generateOneTimeCode()

    try:
        comunicator.send_email_template(
            templateName='activation.html',
            to=user.get('email', None),
            subject="Your account activation code",
            code=code
        )
    except Exception as error:
        raise HTTPException(500, "Unable to send email")
    
    AuthCodesDB.insert({
        "code": code,
        "userId": user.get('_id'),
        "method": "email",
        "type": "activation",
        "expires": datetime.utcnow() + timedelta(minutes=authConfig.Pending_Account_Code_Lifetime)
    })