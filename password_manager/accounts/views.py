"""Custom account views and hardened allauth overrides."""

from django.shortcuts import render, redirect
from django.contrib import messages
from django.contrib.auth import login, logout
from django.contrib.auth.decorators import login_required
from django.views.decorators.http import require_POST
from allauth.account.views import (
    PasswordResetFromKeyView,
    INTERNAL_RESET_SESSION_KEY,
)
from allauth.mfa.models import Authenticator
from allauth.mfa.totp.internal.auth import get_totp_secret
from allauth.mfa.utils import is_mfa_enabled
from allauth.mfa.totp.internal.auth import validate_totp_code
from .models import CustomUser
from core.logging_utils import get_accounts_logger
import qrcode
import io
import base64
import secrets
import string

# Get centralized logger
logger = get_accounts_logger()


class HardenedPasswordResetFromKeyView(PasswordResetFromKeyView):
    """Ensure invalid password reset links cannot expose the reset form."""

    def render_to_response(self, context, **response_kwargs):
        if context.get("token_fail"):
            # Clear any stale token data to prevent reuse attempts.
            self.request.session.pop(INTERNAL_RESET_SESSION_KEY, None)
            messages.error(
                self.request,
                "The password reset link is invalid or has expired. "
                "Please request a new password reset email.",
            )
            return redirect('account_reset_password')
        return super().render_to_response(context, **response_kwargs)

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


def get_recovery_codes_data(codes):
    """
    Generate the data structure that allauth expects for recovery codes
    """
    # Generate a seed for the recovery codes
    seed = secrets.token_bytes(32)
    
    return {
        'seed': seed.hex(),  # This is what allauth expects
        'unused_codes': codes  # Keep this for compatibility with existing views
    }


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
    user = request.user

    if Authenticator.objects.filter(user=user, type=Authenticator.Type.TOTP).exists():
        messages.warning(request, '2FA is already enabled for your account.')
        return redirect('security_settings')

    # Use existing secret from session if available
    secret = request.session.get('totp_secret')
    if not secret:
        secret = get_totp_secret(user)
        request.session['totp_secret'] = secret

    if request.method == 'POST':
        code = request.POST.get('code')

        if not secret:
            messages.error(request, 'Session expired. Please try again.')
            return redirect('enable_2fa')

        if validate_totp_code(secret, code):
            Authenticator.objects.create(
                user=user,
                type=Authenticator.Type.TOTP,
                data={'secret': secret}
            )
            codes = generate_recovery_codes()
            # Use the proper data structure with 'seed' key
            recovery_data = get_recovery_codes_data(codes)
            Authenticator.objects.create(
                user=user,
                type=Authenticator.Type.RECOVERY_CODES,
                data=recovery_data
            )
            del request.session['totp_secret']
            logger.info(f"2FA enabled for user: {user.email}")
            messages.success(request, '2FA has been successfully enabled!')
            request.session['new_recovery_codes'] = codes
            return redirect('show_recovery_codes')
        else:
            messages.error(request, 'Invalid code. Please try again.')

    # Generate QR code using the current secret
    totp_uri = f"otpauth://totp/{user.email}?secret={secret}&issuer=Password%20Manager"
    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(totp_uri)
    qr.make(fit=True)

    # Convert QR code to base64 string
    img = qr.make_image(fill_color="black", back_color="white")
    buffer = io.BytesIO()
    img.save(buffer, format='PNG')
    buffer.seek(0)
    qr_code_data = base64.b64encode(buffer.getvalue()).decode()

    context = {
        'secret': secret,
        'qr_code_data': qr_code_data,
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
        recovery_data = get_recovery_codes_data(codes)

        # Update or create recovery codes authenticator
        recovery_auth, created = Authenticator.objects.get_or_create(
            user=user,
            type=Authenticator.Type.RECOVERY_CODES,
            defaults={'data': recovery_data}
        )

        if not created:
            recovery_auth.data = recovery_data
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
                login(request, user, backend="allauth.account.auth_backends.AuthenticationBackend")

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