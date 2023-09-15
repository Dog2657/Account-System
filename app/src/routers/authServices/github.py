from core.auth.auth import login_with_external_service, connect_external_service, getRedirectUri
from fastapi import APIRouter, HTTPException, Response, Depends
from core.auth.dependencies import getUserFromAccessToken
from fastapi.responses import RedirectResponse
from core import environment, auth
import requests

router = APIRouter()

# -------------------------------------- #

client_id = environment.get('Github_Id')
client_secret = environment.get('Github_Secret')

# -------------------------------------- #

def getUserFromToken(token: str):
    response = requests.post(
        "https://github.com/login/oauth/access_token",
        headers={"Accept": "application/json"},
        data={
            "client_id": client_id,
            "client_secret": client_secret,
            "code": token,
        }
    )
    if response.status_code != 200:
        return {"error": "Failed to retrieve access token"}

    access_token = response.json()["access_token"]

    emailResponce = requests.get('https://api.github.com/user/emails', headers={
        "Authorization": f"token {access_token}",
        "Accept": "application/json",
        "X-GitHub-Api-Version": "2022-11-28",
    })
    if emailResponce.status_code != 200:
        raise HTTPException(status_code=500, detail="Failed to fetch user email")
    
    primary_email = next((email for email in emailResponce.json() if email['primary']), None).get('email')
    
    response = requests.get("https://api.github.com/user", headers={
        "Authorization": f"Bearer {access_token}",
        "Accept": "application/vnd.github.v3+json",
    })
    if response.status_code != 200:
        raise HTTPException(status_code=500, detail="Failed to fetch user profile")
    
    userdata = response.json()
    return str(userdata['id']), primary_email, userdata["login"], userdata['avatar_url']

# -------------------------------------- #

@router.get('/connect-github', tags=['Connect Github'])
async def GET_Connect():
    redirect_uri = getRedirectUri("connect-github/auth")
    return RedirectResponse(f"https://github.com/login/oauth/authorize?client_id={client_id}&redirect_uri={redirect_uri}&scope=read:user:email,user")

@router.get('/connect-github/auth', tags=['Connect Github'])
async def Connect_Discord(code: str, user = Depends( getUserFromAccessToken )):
    user_id, email, username, profile_image =  getUserFromToken(code)
    connect_external_service("github", user_id, username, user)


# -------------------------------------- #

@router.get('/login-with-github', tags=['Login with Github'])
async def Login():
    redirect_uri = getRedirectUri("login-with-github/auth")
    return RedirectResponse(f"https://github.com/login/oauth/authorize?client_id={client_id}&redirect_uri={redirect_uri}&scope=read:user:email,user")


@router.get('/login-with-github/auth', tags=['Login with Github'])
async def Auth_Responce(response: Response, code: str):
    user_id, email, username, profile_image = getUserFromToken(code)
    return login_with_external_service(response, "github", user_id, email, username, profile_image)