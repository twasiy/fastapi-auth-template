class EmailSubjects:
    ACTIVATION: str = "Activate your account"
    VERIFY_EMAIL: str = "Verify your email address"
    RESET_PASSWORD: str = "Reset your password"
    PASSWORD_CHANGED: str = "Security alert: Your password was changed"
    VERIFY_PHONE: str = "Verify your phone number"
    PHONE_CHANGED: str = "Security alert: Your phone number was changed"
    CHANGE_EMAIL: str = "Confirm your new email address"
    EMAIL_CHANGED: str = "Security alert: Your email address was changed"


class Path:
    ACTIVATE: str = "activate"
    RESET_PASSWORD: str = "reset-password"
    VERIFY_EMAIL: str = "verify-email"
    CHANGE_EMAIL: str = "change-email"


class Template:
    ACTIVATION: str = "activation.html"
    VERIFICATION: str = "verification.html"
    EMAIL_CHANGE: str = "email_change.html"
    RESET_PASSWORD: str = "reset_password.html"


subjects = EmailSubjects()
paths = Path()
templates = Template()
