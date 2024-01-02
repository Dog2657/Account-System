from fastapi import APIRouter, HTTPException, Form, Depends
from config import auth as authConfig

from .discord import router as DiscordRouter
from .github import router as GithubRouter
from .facebook import router as FacebookRouter
from .google import router as GoogleRouter

router = APIRouter()

router.include_router(DiscordRouter)
router.include_router(GithubRouter)
router.include_router(FacebookRouter)
router.include_router(GoogleRouter)

#------------------------------------#

from core.auth.auth import generate_pending_account_token_response, checkIfServiceConnected
from core.auth.dependencies import decode_Token, getUserFromAccessToken
from database.connections import UserDB, PendingUserDB
from core.security.security import hash_password
from datetime import datetime, timedelta
from database.models import PendingUser
from core import validation as validate
from dataclasses import asdict
from typing import Annotated

@router.delete("/disconnect-service/{serviceName}")
def DELETE_Service_Connection(serviceName: str, user = Depends(getUserFromAccessToken)):
    if(not checkIfServiceConnected(user, serviceName.lower())):
        raise HTTPException(404, "No service with this name linked")
    
    UserDB.update({"$pull": {'services':{ 'name': serviceName.lower() }}})


@router.post('/create-account-with-service', tags=['Signup'])
def POST_Create_Account_With_service(token: str, username: Annotated[str, Form()], password: Annotated[str, Form()]):
    type, _, serviceName, serviceUserId, serviceUsername, email = decode_Token(token, 'account_creation_with_serivce').values()

    if(UserDB.find({"services": {"name": serviceName, "id": serviceUserId} })):
        raise HTTPException(400, f"This external service account is already connected to an account")
    
    if( PendingUserDB.find({'$or': [ {"email": email.lower()}, {"username": {'$regex': f'^{username}$', "$options": 'i'} } ]}) ):
        raise HTTPException(400, "Account already made and awaiting activation")
    
    if(UserDB.findUserByEmail(email)):
        raise HTTPException(400, "We've already got an account with this email address")

    if(UserDB.findUserByUsername(username)):
        raise HTTPException(400, "Username already taken")

    if(not validate.password(password)):
        raise HTTPException(400, "Password is week")
    
    expires = datetime.utcnow() + authConfig.Pending_Accounts_Lifetime_Token

    account = PendingUser(email, expires, username, hash_password(password))
    account.service = {
        'name': serviceName,
        'id': serviceUserId,
        'username': serviceUsername
    }

    id = PendingUserDB.insert(asdict( account ))
    return generate_pending_account_token_response(id, email, username, expires, [ {"name": serviceName, "id": serviceUserId} ])