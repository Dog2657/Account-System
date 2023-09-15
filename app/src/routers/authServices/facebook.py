from core.auth.auth import login_with_external_service, connect_external_service, getRedirectUri
from fastapi import APIRouter, HTTPException, Response, Depends
from core.auth.dependencies import getUserFromAccessToken
from fastapi.responses import RedirectResponse
from core import environment, auth
from urllib.parse import urlencode
import requests

router = APIRouter()

# -------------------------------------- #

client_id = environment.get('Facebook_Id')
client_secret = environment.get('Facebook_Secret')

# -------------------------------------- #

def getUserFromToken(token: str, redirect_path: str):
    response = requests.get("https://graph.facebook.com/v4.0/oauth/access_token", params={
        "client_id": client_id,
        "redirect_uri": getRedirectUri(redirect_path),
        "client_secret": client_secret,
        "code": token,
    })
    
    if not response.ok:
        raise HTTPException(status_code=500, detail="Failed to fetch user profile")

    access_token = response.json().get('access_token')
    
    response = requests.get(f'https://graph.facebook.com/v10.0/me?fields=email,name,picture&access_token={access_token}')
    if not response.ok:
        raise HTTPException(status_code=500, detail="Failed to fetch user profile")

    details = response.json()
    return details['id'], details['email'], details['name'], details['picture']['data']['url']

# -------------------------------------- #

@router.get('/connect-facebook', tags=['Connect Facebook'])
async def GET_Connect():
    redirect_uri = getRedirectUri("connect-facebook/auth")
    return RedirectResponse("https://www.facebook.com/v4.0/dialog/oauth?" + urlencode({
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "state": "your-csrf-token",
        "response_type": "code",
        "scope": "public_profile email",
    }))

@router.get('/connect-facebook/auth', tags=['Connect Facebook'])
async def Connect_Discord(code: str, user = Depends( getUserFromAccessToken )):
    user_id, email, username, profile_image = getUserFromToken(code, "connect-facebook/auth")
    connect_external_service("facebook", user_id, username, user)

# -------------------------------------- #

@router.get('/login-with-facebook/', tags=['Login with Facebook'])
async def Login():
    redirect_uri = getRedirectUri("login-with-facebook/auth")
    return RedirectResponse("https://www.facebook.com/v4.0/dialog/oauth?" + urlencode({
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "state": "your-csrf-token",
        "response_type": "code",
        "scope": "public_profile email",
    }))


@router.get('/login-with-facebook/auth', tags=['Login with Facebook'])
async def Auth_Responce(response: Response, code: str):
    user_id, email, username, profile_image = getUserFromToken(code, "login-with-facebook/auth")
    return login_with_external_service(response, "facebook", user_id, email, username, profile_image)