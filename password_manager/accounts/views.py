# Import necessary modules and models
from django.shortcuts import render, redirect
from django.contrib import messages
from django.contrib.auth import authenticate, login, logout
from .models import CustomUser
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

    # Check if the HTTP request method is POST (form submission)
    if request.method == 'POST':
        email = request.POST.get('email')
        password = request.POST.get('password')

        logger.info(f"Registration attempt.")

        # Check if a user with the provided username already exists
        user = CustomUser.objects.filter(email=email)

        if user.exists():
            # Display an information message if the username is taken
            logger.warning(f"Registration failed - Email already exists.")
            messages.info(request, "Username already taken!")
            return redirect('/register/')

        # Create a new User object with the provided information
        user = CustomUser.objects.create_user(
            email=email
        )

        # Set the user's password and save the user object
        user.set_password(password)
        user.save()

        # Display an information message indicating successful account creation
        logger.info(f"New user registered successfully: {user.email}")
        messages.info(request, "Account created Successfully!")
        return redirect('/login/')

    # Render the registration page template (GET request)
    return render(request, 'register.html')

def logout_page(request):
    if request.user.is_authenticated:
        logger.info(f"User logged out: {request.user.email}")
    logout(request)
    return redirect('/login/')