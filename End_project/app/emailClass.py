import smtplib

MY_EMAIL = "YOUR_EMAIL"
MY_PASSWORD = "YOUR_PASSWORD"

class EmailClass():
    def __init__(self):
        pass

        # Sending verification code to user email
    def send_verification_email(self, user_email, verification_code):
       with smtplib.SMTP("smtp.gmail.com") as connection:
            message = f"Subject:Email Verification\n\nYour verification code is {verification_code}.\nPlease enter this code in the verification page."
            connection.starttls()
            connection.login(user=MY_EMAIL, password=MY_PASSWORD)
            connection.sendmail(
                from_addr=MY_EMAIL,
                to_addrs=user_email,
                msg=message
            )
        # Sending password reset code to user email
    def send_password_reset_email(self, user_email, reset_code):
        with smtplib.SMTP("smtp.gmail.com") as connection:
            message = f"Subject:Password Reset\n\nYour password reset code is {reset_code}.\nPlease enter this code in the password reset page."
            connection.starttls()
            connection.login(user=MY_EMAIL, password=MY_PASSWORD)
            connection.sendmail(
                from_addr=MY_EMAIL,
                to_addrs=user_email,
                msg=message
            )