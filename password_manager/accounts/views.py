# Import necessary modules and models
from django.shortcuts import render, redirect
from django.contrib import messages
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.db import transaction
from django.http import JsonResponse
from django.views.decorators.http import require_POST
from allauth.mfa.models import Authenticator
from allauth.mfa.totp.internal.auth import get_totp_secret
from allauth.mfa.utils import is_mfa_enabled
from allauth.mfa.totp.internal.auth import validate_totp_code
from .models import CustomUser
from vault.encryption_service import EncryptionService
from vault.crypto_utils import CryptoError
import logging
import qrcode
import qrcode.image.svg
from io import BytesIO
import base64
import secrets
import string

# Get logger for accounts app
logger = logging.getLogger('accounts')
alerts_logger = logging.getLogger('alerts')

def generate_recovery_codes(count=10):
    """Generate recovery codes for 2FA backup"""
    codes = []
    for _ in range(count):
        # Generate 8-character alphanumeric codes
        code = ''.join(secrets.choice(string.ascii_uppercase + string.digits) for _ in range(8))
        # Format as XXXX-XXXX for readability
        formatted_code = f"{code[:4]}-{code[4:]}"
        codes.append(formatted_code)
    return codes

# Define a view function for the login page
def login_page(request):
    logger.info(f"Login page accessed from IP: {request.META.get('REMOTE_ADDR')}")

    if request.user.is_authenticated:
        logger.info(f"Already authenticated user {request.user.email} redirected to home")
        return redirect('/home')

    # Check if the HTTP request method is POST (form submission)
    if request.method == "POST":
        email = request.POST.get('email')
        password = request.POST.get('password')

        logger.info("Login attempt.")

        # Check if a user with the provided username exists
        if not CustomUser.objects.filter(email=email).exists():
            # Display an error message if the username does not exist
            logger.warning(f"Login failed - Email not found. from IP: {request.META.get('REMOTE_ADDR')}")
            messages.error(request, "Email and Password do not match")
            return redirect("/login/")

        # Authenticate the user with the provided username and password
        user = authenticate(email=email, password=password)

        if user is None:
            # Display an error message if authentication fails (invalid password)
            logger.warning(f"Login failed - Invalid password from IP: {request.META.get('REMOTE_ADDR')}")
            alerts_logger.error("Failed login attempt detected.")
            messages.error(request, "Email and Password do not match")
            return redirect("/login/")
        else:
            # Log in the user and redirect to the home page upon successful login
            logger.info(f"Successful login for user: {email}")
            login(request, user)
            return redirect("/home/")

    # Render the login page template (GET request)
    return render(request, "login.html")


# Define a view function for the registration page
def register_page(request):
    logger.info(f"Registration page accessed from IP: {request.META.get('REMOTE_ADDR')}")

    if request.user.is_authenticated:
        logger.info(f"Already authenticated user {request.user.email} redirected to home")
        return redirect('/home')

    # Check if the HTTP request method is POST (form submission)
    if request.method == "POST":
        email = request.POST.get('email')
        password = request.POST.get('password')
        confirm_password = request.POST.get('confirm_password')

        logger.info(f"Registration attempt for email: {email}")

        # Validate input
        if not email or not password:
            messages.error(request, 'Email and password are required')
            return redirect('/register/')

        if password != confirm_password:
            messages.error(request, 'Passwords do not match')
            return redirect('/register/')

        # Check if user already exists
        if CustomUser.objects.filter(email=email).exists():
            logger.warning(f"Registration failed - Email already exists: {email}")
            messages.error(request, 'Email already exists')
            return redirect('/register/')

        try:
            # Create user and set up encryption in a transaction
            with transaction.atomic():
                # Create the user (Django handles Argon2 password hashing)
                user = CustomUser.objects.create_user(email=email, password=password)

                # Set up encryption for the new user
                EncryptionService.setup_user_encryption(user)

                logger.info(f"Successfully registered user: {email} with encryption setup")
                messages.success(request, 'Registration successful! Please log in.')
                return redirect('/login/')

        except CryptoError as e:
            logger.error(f"Encryption setup failed for user {email}: {str(e)}")
            messages.error(request, 'Registration failed due to encryption error')
            return redirect('/register/')
        except Exception as e:
            logger.error(f"Registration failed for user {email}: {str(e)}")
            messages.error(request, 'Registration failed')
            return redirect('/register/')

    # Render the registration page template (GET request)
    return render(request, 'register.html')

def logout_page(request):
    if request.user.is_authenticated:
        logger.info(f"User logged out: {request.user.email}")
    logout(request)
    return redirect('/login/')

@login_required
def profile_view(request):
    """User profile overview with links to security settings"""
    context = {
        'user': request.user,
        'mfa_enabled': is_mfa_enabled(request.user),
        'authenticators': Authenticator.objects.filter(user=request.user),
    }
    return render(request, 'accounts/profile.html', context)

@login_required
def security_settings(request):
    """Security settings page with 2FA management"""
    user = request.user
    mfa_enabled = is_mfa_enabled(user)
    totp_authenticators = Authenticator.objects.filter(
        user=user,
        type=Authenticator.Type.TOTP
    )

    context = {
        'user': user,
        'mfa_enabled': mfa_enabled,
        'totp_authenticators': totp_authenticators,
        'has_recovery_codes': Authenticator.objects.filter(
            user=user,
            type=Authenticator.Type.RECOVERY_CODES
        ).exists(),
    }
    return render(request, 'accounts/security_settings.html', context)

@login_required
def enable_2fa(request):
    """Enable 2FA with TOTP authenticator"""
    user = request.user

    # Check if TOTP is already enabled
    if Authenticator.objects.filter(user=user, type=Authenticator.Type.TOTP).exists():
        messages.warning(request, '2FA is already enabled for your account.')
        return redirect('security_settings')

    if request.method == 'POST':
        code = request.POST.get('code')
        secret = request.session.get('totp_secret')

        if not secret:
            messages.error(request, 'Session expired. Please try again.')
            return redirect('enable_2fa')

        # Verify the TOTP code
        if validate_totp_code(secret, code):
            # Create the TOTP authenticator
            Authenticator.objects.create(
                user=user,
                type=Authenticator.Type.TOTP,
                data={'secret': secret}
            )

            # Generate recovery codes
            codes = generate_recovery_codes()
            Authenticator.objects.create(
                user=user,
                type=Authenticator.Type.RECOVERY_CODES,
                data={'unused_codes': codes}
            )

            # Clear session
            del request.session['totp_secret']

            logger.info(f"2FA enabled for user: {user.email}")
            messages.success(request, '2FA has been successfully enabled!')

            # Show recovery codes
            request.session['new_recovery_codes'] = codes
            return redirect('show_recovery_codes')
        else:
            messages.error(request, 'Invalid code. Please try again.')


    secret = get_totp_secret(user)
    request.session['totp_secret'] = secret

    # Generate QR code
    totp_uri = f"otpauth://totp/{user.email}?secret={secret}&issuer=Password%20Manager"
    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(totp_uri)
    qr.make(fit=True)

    # Create QR code image
    img = qr.make_image(fill_color="black", back_color="white")
    buffer = BytesIO()
    img.save(buffer, format='PNG')
    img_data = base64.b64encode(buffer.getvalue()).decode()

    context = {
        'secret': secret,
        'qr_code_data': img_data,
        'totp_uri': totp_uri,
    }
    return render(request, 'accounts/enable_2fa.html', context)

@login_required
@require_POST
def disable_2fa(request):
    """Disable 2FA for the user"""
    user = request.user

    # Remove all authenticators
    deleted_count = Authenticator.objects.filter(user=user).delete()[0]

    if deleted_count > 0:
        logger.info(f"2FA disabled for user: {user.email}")
        messages.success(request, '2FA has been disabled for your account.')
    else:
        messages.info(request, '2FA was not enabled for your account.')

    return redirect('security_settings')

@login_required
def regenerate_recovery_codes(request):
    """Regenerate recovery codes"""
    user = request.user

    if request.method == 'POST':
        # Generate new recovery codes
        codes = generate_recovery_codes()

        # Update or create recovery codes authenticator
        recovery_auth, created = Authenticator.objects.get_or_create(
            user=user,
            type=Authenticator.Type.RECOVERY_CODES,
            defaults={'data': {'unused_codes': codes}}
        )

        if not created:
            recovery_auth.data = {'unused_codes': codes}
            recovery_auth.save()

        logger.info(f"Recovery codes regenerated for user: {user.email}")
        messages.success(request, 'New recovery codes generated!')

        # Show new recovery codes
        request.session['new_recovery_codes'] = codes
        return redirect('show_recovery_codes')

    return render(request, 'accounts/regenerate_recovery_codes.html')

@login_required
def show_recovery_codes(request):
    """Show recovery codes to user"""
    codes = request.session.get('new_recovery_codes')

    if not codes:
        messages.error(request, 'No recovery codes to display.')
        return redirect('security_settings')

    context = {'recovery_codes': codes}
    return render(request, 'accounts/show_recovery_codes.html', context)

def recovery_code_login(request):
    """Allow users to authenticate using recovery codes"""
    if request.user.is_authenticated:
        return redirect('home')

    if request.method == 'POST':
        email = request.POST.get('email')
        recovery_code = request.POST.get('recovery_code', '').strip().upper()

        if not email or not recovery_code:
            messages.error(request, 'Please provide both email and recovery code.')
            return render(request, 'accounts/recovery_login.html')

        try:
            user = CustomUser.objects.get(email=email)

            # Get the user's recovery codes
            recovery_auth = Authenticator.objects.filter(
                user=user,
                type=Authenticator.Type.RECOVERY_CODES
            ).first()

            if not recovery_auth:
                messages.error(request, 'No recovery codes found for this account.')
                return render(request, 'accounts/recovery_login.html')

            unused_codes = recovery_auth.data.get('unused_codes', [])

            if recovery_code in unused_codes:
                # Remove the used code
                unused_codes.remove(recovery_code)
                recovery_auth.data['unused_codes'] = unused_codes
                recovery_auth.save()

                # Log the user in
                from django.contrib.auth import login
                login(request, user)

                logger.info(f"User {user.email} authenticated using recovery code")
                messages.success(request, 'Successfully authenticated using recovery code.')

                # Warn if running low on codes
                if len(unused_codes) <= 2:
                    messages.warning(request, f'You have {len(unused_codes)} recovery codes remaining. Consider regenerating new codes.')

                return redirect('home')
            else:
                logger.warning(f"Invalid recovery code attempt for user: {email}")
                messages.error(request, 'Invalid recovery code.')

        except CustomUser.DoesNotExist:
            logger.warning(f"Recovery code login attempt for non-existent user: {email}")
            messages.error(request, 'Invalid email or recovery code.')

    return render(request, 'accounts/recovery_login.html')

