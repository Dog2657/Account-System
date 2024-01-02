from datetime import timedelta


#The time before an access token becomes invalid
Access_Token_Lifetime = timedelta(hours=2)

#The time till the 2fa tokens expire
Twofa_Token_Lifetime = timedelta(minutes=30)


#Used for password reset links when a "forgot password" email is sent
Password_Reset_Token_Lifetime = timedelta(minutes=15)


#The time till a 2fa setup token expires
Time_2fa_Activation_Token_Lifetime = timedelta(hours=15)


#Used for access when user hasn't verified their email address
Pending_Accounts_Lifetime_Token =  timedelta(hours=1)

#Used to validate email addresses when making new accounts
#In minutes
Pending_Account_Code_Lifetime = timedelta(minutes=15)

#Used when crateing an account with external services (Google, Facebook, Discord, Github etc)
Service_Account_Creation_Lifetime = timedelta(minutes=15)