from core.security.security import verify_password, hash_password, encodeTimeToken, encodeToken, generateOneTimeCode
from database.connections import UserDB, AuthCodesDB, invalidAccessTokensDB, AuthCodesDB
from fastapi import APIRouter, Depends, Form, HTTPException, Response, Cookie
from core.auth.dependencies import getUserFromAccessToken, decode_Token
from config import email as emailConfig, phone as phoneConfig
from core import comunicator, validation as validate
from .twofa import router as Account2faRouter
from datetime import datetime, timedelta
from core.auth.auth import login_user
from typing import Annotated

router = APIRouter()

router.include_router(Account2faRouter)

@router.patch("/change-username", tags=["Change Account Details"])
async def PATCH_Update_Username(username: Annotated[str, Form()], account = Depends(getUserFromAccessToken)):
    if(username == account.get("username")):
        raise HTTPException(400, "You already have this username")

    if(UserDB.findUserByUsername(username)):
        raise HTTPException(401, "Username already taken")
    
    UserDB.update({"$set": {"username": username}}, id=account.get("_id"))


@router.patch('/change-password', tags=["Change Account Details"])
async def PATCH_Update_Password(response: Response, old_password: Annotated[str, Form()], new_password: Annotated[str, Form()], account = Depends(getUserFromAccessToken)):
    if(not verify_password(old_password, account.get("passwordHash"))):
        raise HTTPException(401, "Password it incorrect")
    
    if(verify_password(new_password, account.get("passwordHash"))):
        raise HTTPException(401, "This is already your password")
    
    UserDB.update({"$set": {
        "passwordHash": hash_password(new_password),
        "lastPasswordChange": datetime.utcnow()
    }}, id=account.get("_id"))

    return login_user(response, account.get("_id"))



@router.patch("/change-email", tags=["Change Email"])
async def PATCH_Update_Email_Address(address: Annotated[str, Form()], account = Depends(getUserFromAccessToken)):
    if(UserDB.findUserByEmail(address)):
        raise HTTPException(400, "Email already in use")

    if(not validate.email(address)):
        raise HTTPException(400, "Invalid email address")

    search = AuthCodesDB.find({"type": "change-email", "userId": account.get("_id")})
    if(search):
        raise HTTPException(401, f"Still on cooldown till ({search.get('expires')})")

    del search

    token = encodeTimeToken({
        "type": "email_change",
        "address": address,
        "userId": account.get("_id"),
    }, Minutes=emailConfig.Email_Change_Token_Lifetime)

    #TODO: add front end client password reset uri 

    comunicator.send_email_template(
        "email_change.html",
        account.get('email'),
        "Change your email",
        username=account.get("username"),
        address=address,
        link=f"https://yoursite.com/change-password/{token}"
    )

    AuthCodesDB.insert({
        "type": "change-email",
        "userId": account.get("_id"),
        "token": token,
        "expires": datetime.utcnow() + timedelta(minutes=emailConfig.Email_Change_Token_Lifetime)
    })

@router.patch("/change-email/{token}", tags=["Change Email"])
async def PATCH_Set_Updated_Email(token: str):
    decoded = decode_Token(token, "email_change")

    UserDB.update({"$set": {"email": decoded.get('address')}}, id=decoded.get("userId"))

    AuthCodesDB.delete({"type": "change-email", "token": token})



@router.post('/update-phone-number', tags=['Change Phone Number'])
async def POST_Start_Phone_Number_Update(number: Annotated[str, Form()], account = Depends(getUserFromAccessToken)):
    if(not validate.phone_number(number)):
        raise HTTPException(400, "Invalid phone number")
    
    expires = datetime.utcnow() + timedelta(minutes=phoneConfig.Add_Phone_Token_Lifetime )  

    token = encodeToken({
        "userId": account.get("_id"),
        "type": "Add_Phone_Number",
        "number": number,
        "exp": expires,
    })

    return {
        'type': "Add_Phone_Number",
        'token': token,
        'token_expires': expires.strftime("%m/%d/%Y %H:%M:%S")
    }

@router.patch('/update-phone-number/resend-code/{token}', tags=['Change Phone Number'])
async def PATCH_Resend_Phone_Update_Code(token: str, account = Depends(getUserFromAccessToken)):
    details = decode_Token(token, "Add_Phone_Number")

    if(details.get('userId') != account.get("_id")):
        raise HTTPException(401, "this token is for another user")

    search = AuthCodesDB.find({"userId": account.get("_id"), "type": "Add_Phone_Number", "method": 'phone'})
    if(search):
        if( search.get('expires') <= datetime.utcnow()):
            AuthCodesDB.delete(id=search.get('_id'))
        else:
            raise HTTPException(401, f"Still on cooldown till ({search.get('expires')})")

    code = generateOneTimeCode()

    try:
        comunicator.send_sms_template(
            templateName='add_number.txt',
            to=details.get("number", None),
            code=code
        )
    except Exception as error:
        raise HTTPException(500, "Unable to send text message")
    
    AuthCodesDB.insert({
        "userId": account.get("_id"),
        "type": "Add_Phone_Number",
        "method": "phone",
        "code": code,
        "expires": datetime.utcnow() + timedelta(minutes=phoneConfig.Add_Phone_Code_Lifetime)
    })

@router.patch('/update-phone-number/{token}', tags=['Change Phone Number'])
async def PATCH_Resend_Phone_Update_Code(code: Annotated[str, Form()], token: str, account = Depends(getUserFromAccessToken)):
    details = decode_Token(token, "Add_Phone_Number")

    if(details.get('userId') != account.get("_id")):
        raise HTTPException(401, "this token is for another user")
    
    if(details.get('number') == account.get('phone', "")):
        raise HTTPException(400, "Token already used")
    
    search = AuthCodesDB.find({"userId": account.get("_id"), "type": "Add_Phone_Number", "method": 'phone'})
    if(not search):
        raise HTTPException(401, "No active codes found")
    
    if( search.get('expires') <= datetime.utcnow()):
        AuthCodesDB.delete(id=search.get('_id'))
        raise HTTPException(401, "No active codes found")
    
    if(search.get('code') != code):
        raise HTTPException(401, "Code is invalid")
    
    UserDB.update({"$set": {"phone": details.get('number')}}, id=account.get("_id"))


@router.post('/logout', dependencies=[ Depends(getUserFromAccessToken) ])
async def POST_Logout(response: Response, access_token: Annotated[str | None, Cookie()] = None):
    token = decode_Token(access_token, "access")

    invalidAccessTokensDB.insert({
        "expires": datetime.fromtimestamp(token.get('exp')),
        "token": access_token 
    })
    
    response.delete_cookie('access_token')
