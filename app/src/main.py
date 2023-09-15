from fastapi.middleware.cors import CORSMiddleware
from fastapi import FastAPI

from routers.auth import router as AuthRouter
from routers.registration import router as registrationRouter
from routers.accountDetails import graphql_app as accountDetailsRouter
from routers.account import router as accountRouter
from routers.authServices.router import router as External_Services_Router

app = FastAPI()

with open('../Allowed_Origins.txt') as file:
    origins = file.read().split('\n')
    
app.include_router(AuthRouter)
app.include_router(registrationRouter)
app.include_router(accountRouter)
app.include_router(External_Services_Router)
app.include_router(accountDetailsRouter, prefix="/graphql/account-details", tags=["Get User Details"])

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)