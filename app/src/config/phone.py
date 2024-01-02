from datetime import timedelta

#This is the duation of 2fa sms login codes
Phone_2fa_Auth_Code_Lifetime = timedelta(minutes=15)

#The duration before an phone number update token expires
Add_Phone_Token_Lifetime = timedelta(minutes=15)

#This is the duration of add phone number codes
#Its used to verify phone numbers before setting them to a user account
Add_Phone_Code_Lifetime = timedelta(minutes=5)

#Used to activate phone 2fa
Phone_2fa_Activation_Token_Lifetime = timedelta(minutes=15)

#Used for disableing phone 2fa
Phone_2fa_Deactivation_Token = timedelta(minutes=15)