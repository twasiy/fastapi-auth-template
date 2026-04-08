from twilio.base.exceptions import TwilioRestException
from twilio.rest import Client

from app.core import settings

client = Client(settings.TWILIO_ACCOUNT_SID, settings.TWILIO_AUTH_TOKEN)


def send_sms(phone: str, otp: str):
    try:
        message = client.messages.create(
            body=f"Your verification code is: {otp}. It expires in 5 minutes.",
            from_=settings.TWILIO_PHONE_NUMBER,
            to=phone,
        )
        return message.sid
    except TwilioRestException as e:
        print(f"Error sending SMS: {e}")
        return None
