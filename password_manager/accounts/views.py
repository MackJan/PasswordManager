# Import necessary modules and models
from django.shortcuts import render, redirect
from django.contrib import messages
from django.contrib.auth import authenticate, login, logout
from django.db import transaction
from .models import CustomUser
from vault.encryption_service import EncryptionService
from vault.crypto_utils import CryptoError
import logging

# Get logger for accounts app
logger = logging.getLogger('accounts')
alerts_logger = logging.getLogger('alerts')

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

        logger.info(f"Login attempt.")

        # Check if a user with the provided username exists
        if not CustomUser.objects.filter(email=email).exists():
            # Display an error message if the username does not exist
            logger.warning(f"Login failed - Email not found. from IP: {request.META.get('REMOTE_ADDR')}")
            messages.error(request, 'Invalid Email')
            return redirect('/login/')

        # Authenticate the user with the provided username and password
        user = authenticate(email=email, password=password)

        if user is None:
            # Display an error message if authentication fails (invalid password)
            logger.warning(f"Login failed - Invalid password from IP: {request.META.get('REMOTE_ADDR')}")
            alerts_logger.error(f"Failed login attempt detected.")
            messages.error(request, "Invalid Password")
            return redirect('/login/')
        else:
            # Log in the user and redirect to the home page upon successful login
            logger.info(f"Successful login for user: {email}")
            login(request, user)
            return redirect('/home/')

    # Render the login page template (GET request)
    return render(request, 'login.html')


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