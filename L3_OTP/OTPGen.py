import pyotp
import time
# secret has been made and fixed for Doki user, this is mainly just for creating OTPs on a separate terminal
base32secret = 'XW2N22IL7UKDSM4DM3DJNNRN56VCKVTK'
timed_otp = pyotp.TOTP(base32secret)
timed_otp.now()
print(timed_otp.now())