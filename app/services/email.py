from fastapi_mail import FastMail, MessageSchema, MessageType
from pydantic import EmailStr, NameEmail

from app.core import settings
from app.models import User


async def send_email(
    user: User,
    email_to: EmailStr,
    token: str,
    subject: str,
    template_name: str,
    path: str,
) -> None:
    url = f"{settings.FRONTEND_HOST}/{path}?token={token}"
    recipient = NameEmail(name=f"{user.first_name}", email=email_to)

    template_data = {
        "body": {
            "full_name": f"{user.first_name} {user.last_name}",
            "username": f"{user.username}",
            "url": url,
        }
    }

    message = MessageSchema(
        subject=subject,
        recipients=[recipient],
        template_body=template_data,
        subtype=MessageType.html,
    )

    fm = FastMail(settings.mail_config)
    try:
        await fm.send_message(message=message, template_name=template_name)
    except Exception as e:
        print(f"Failed to send email: {e}")
