from core.auth.auth import login_with_external_service, connect_external_service, getRedirectUri
from fastapi import APIRouter, HTTPException, Response, Depends
from core.auth.dependencies import getUserFromAccessToken
from fastapi.responses import RedirectResponse
from core import environment
import requests

router = APIRouter()

# -------------------------------------- #

client_id = environment.get('Google_Id')
client_secret = environment.get('Google_Secret')

# -------------------------------------- #

def getUserFromToken(token: str, redirect_path: str):
    tokenResponse = requests.post("https://accounts.google.com/o/oauth2/token", data={
        "code": token,
        "client_id": client_id,
        "client_secret": client_secret,
        "redirect_uri": getRedirectUri(redirect_path),
        "grant_type": "authorization_code"
    })
    if not tokenResponse.ok:
        raise HTTPException(status_code=500, detail="Failed to get access token")
    
    access_token = tokenResponse.json()["access_token"]
    
    detailsResponse = requests.get(
        "https://www.googleapis.com/oauth2/v2/userinfo",
        headers={ "Authorization": f"Bearer {access_token}" }
    )
    if not detailsResponse.ok:
        raise HTTPException(status_code=500, detail="Failed to fetch user profile")

    details = detailsResponse.json()
    return details["id"], details['email'], details["name"], details['picture']

# -------------------------------------- #

@router.get('/connect-google', tags=['Connect Google'])
async def GET_Connect():
    redirect_uri = getRedirectUri("connect-google/auth")
    return RedirectResponse(f"https://accounts.google.com/o/oauth2/auth?client_id={client_id}&redirect_uri={redirect_uri}&scope=email profile&response_type=code")

@router.get('/connect-google/auth', tags=['Connect Google'])
async def Connect_Discord(code: str, user = Depends( getUserFromAccessToken )):
    user_id, email, username, profile_image = getUserFromToken(code, "connect-google/auth")
    connect_external_service("google", user_id, username, user)


# -------------------------------------- #

@router.get('/login-with-google', tags=['Login with Google'])
async def Login():
    redirect_uri = getRedirectUri("login-with-google/auth")
    return RedirectResponse(f"https://accounts.google.com/o/oauth2/auth?client_id={client_id}&redirect_uri={redirect_uri}&scope=email profile&response_type=code")


@router.get('/login-with-google/auth', tags=['Login with Google'])
async def Auth_Responce(response: Response, code: str):
    user_id, email, username, profile_image = getUserFromToken(code, "login-with-google/auth")
    return login_with_external_service(response, 'google',  user_id, email, username, profile_image)