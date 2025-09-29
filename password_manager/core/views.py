from django.http import HttpResponse
from django.template import loader
from django.shortcuts import redirect
import logging

# Get logger for core app
logger = logging.getLogger('core')

def home(request):
    logger.info(f"Home page accessed from IP: {request.META.get('REMOTE_ADDR')}")
    if request.user.is_authenticated:
        logger.info(f"Authenticated user {request.user.email} accessed home page")

    template = loader.get_template('home.html')
    context = {
        "authenticated": request.user.is_authenticated,
        "user_email": request.user.email if request.is_authenticated else None,
    }
    return HttpResponse(template.render(context,request))

def root(request):
    logger.info(f"Root redirect accessed from IP: {request.META.get('REMOTE_ADDR')}")
    return redirect("/home/")