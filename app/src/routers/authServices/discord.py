from core.auth.auth import login_with_external_service, connect_external_service, getRedirectUri
from fastapi import APIRouter, HTTPException, Response, Depends
from core.auth.dependencies import getUserFromAccessToken
from fastapi.responses import RedirectResponse
from core import environment
import requests

router = APIRouter()

# -------------------------------------- #

client_id = environment.get('Discord_Id')
client_secret = environment.get('Discord_Secret')

# -------------------------------------- #

def getUserFromToken(token: str, redirect_path: str):
    response = requests.post("https://discord.com/api/oauth2/token", data={
        "client_id": client_id,
        "client_secret": client_secret,
        "grant_type": "authorization_code",
        "code": token,
        "redirect_uri": getRedirectUri(redirect_path),
        "scope": "email identify username",
    })
    if response.status_code != 200:
        raise HTTPException(status_code=400, detail="Failed to retrieve access token")

    token_data = response.json()
    access_token = token_data["access_token"]

    user_response = requests.get("https://discord.com/api/v9/users/@me", headers={ "Authorization": f"Bearer {access_token}" } )
    user_data = user_response.json()

    return user_data["id"], user_data.get("email", None), user_data.get("username", None), f"https://cdn.discordapp.com/avatars/{user_data['id']}/{user_data['avatar']}.png"
    
# -------------------------------------- #

@router.get('/connect-discord', tags=['Connect Discord'])
async def GET_Connect():
    redirect_uri = getRedirectUri("connect-discord/auth")
    return RedirectResponse(f"https://discord.com/api/oauth2/authorize?client_id={client_id}&redirect_uri={redirect_uri}&scope=email identify&response_type=code")

@router.get('/connect-discord/auth', tags=['Connect Discord'])
async def Connect_Discord(code: str, user = Depends( getUserFromAccessToken )):
    user_id, email, username, profile_image = getUserFromToken(code, "connect-discord/auth")
    connect_external_service("discord", user_id, username, user)


# -------------------------------------- #

@router.get('/login-with-discord', tags=['Login with Discord'])
async def Login():
    redirect_uri = getRedirectUri("login-with-discord/auth")
    return RedirectResponse(f"https://discord.com/api/oauth2/authorize?client_id={client_id}&redirect_uri={redirect_uri}&scope=email identify&response_type=code")


@router.get('/login-with-discord/auth', tags=['Login with Discord'])
async def Auth_Responce(response: Response, code: str):
    user_id, email, username, profile_image = getUserFromToken(code, "login-with-discord/auth")
    return login_with_external_service(response, 'discord', user_id, email, username, profile_image)