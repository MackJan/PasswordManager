from django.contrib.auth.decorators import login_required
from django.http import HttpResponse
from django.template import loader
from django.shortcuts import redirect

def home(request):
    template = loader.get_template('home.html')
    context = {
        "authenticated": request.user.is_authenticated,
    }
    return HttpResponse(template.render(context,request))

def root(request):
    return redirect("/home/")