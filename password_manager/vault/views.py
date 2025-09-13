from django.shortcuts import render, redirect

# Create your views here.

def vault_dashboard(request):
    if not request.user.is_authenticated:
        return redirect('/login')
    return render(request, 'dashboard.html')