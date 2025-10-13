from django.http import HttpResponse
from django.template import loader
from django.shortcuts import redirect
from core.logging_utils import get_core_logger

# Get centralized logger
logger = get_core_logger()

def home(request):
    logger.info("Home page accessed", extra_data={"ip": request.META.get('REMOTE_ADDR')})
    user_email = ""

    if request.user.is_authenticated:
        logger.user_activity("home_page_access", request.user)
        user_email = request.user.email
    template = loader.get_template('home.html')
    context = {
        "authenticated": request.user.is_authenticated,
        "user_email": user_email,
    }
    return HttpResponse(template.render(context,request))

def root(request):
    logger.info("Root redirect accessed", extra_data={"ip": request.META.get('REMOTE_ADDR')})
    return redirect("/home/")