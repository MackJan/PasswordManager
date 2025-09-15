from django.shortcuts import render, redirect

from .models import *
from django.contrib import messages

# Create your views here.

def vault_dashboard(request):
    if not request.user.is_authenticated:
        return redirect('/login')
    if request.method == "POST":
        item_name = request.POST.get('name')
        item_username = request.POST.get('username')
        item_password = request.POST.get('password')

        if VaultItem.objects.filter(name=item_name).exists():
            messages.error(request, 'Item already exists')
            return redirect('/vault/')

        item = VaultItem(name=item_name, username=item_username, password=item_password,user_id=request.user.id)
        if item is None:
            messages.error(request, 'Item does not exist')
            return redirect('/vault/')
        else:
            item.save()


    context = {
        "items": VaultItem.objects.all(),
    }
    return render(request, 'dashboard.html',context=context)