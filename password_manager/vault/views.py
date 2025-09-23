from django.shortcuts import render, redirect, get_object_or_404

from .models import VaultItem
from django.contrib import messages

class NameExists(Exception):
    pass

# Create your views here.
def vault_dashboard(request):
    if not request.user.is_authenticated:
        return redirect('/login')
    if request.method == "POST":
        item_name = request.POST.get('name')
        item_username = request.POST.get('username')
        item_password = request.POST.get('password')

        if VaultItem.objects.filter(name=item_name, user=request.user).exists():
            messages.error(request, 'Item with that name already exists')
            return redirect('/vault/')
        try:
            item = VaultItem(name=item_name, username=item_username, password=item_password, user=request.user)

            item.save()
            messages.success(request, f'Item "{item_name}" created successfully!')
        except NameExists:
            messages.error(request, f'Item "{item_name}" already exists!')
        except Exception:
            messages.error(request, 'Something went wrong!')

    context = {
        "items": VaultItem.objects.filter(user=request.user),
    }
    return render(request, 'dashboard.html', context=context)

def edit_dashboard(request):
    if not request.user.is_authenticated:
        return redirect('/login')

    if request.method == "POST":
        item_name = request.POST.get('name')
        item_username = request.POST.get('username')
        item_password = request.POST.get('password')
        item_id = request.POST.get('id')

        try:
            # Get the item and ensure it belongs to the current user
            item = get_object_or_404(VaultItem, id=item_id, user=request.user)

            # Update fields only if they are provided
            if item_name:
                if VaultItem.objects.filter(name=item_name, user=request.user).exists():
                    raise NameExists()
                else:
                    item.name = item_name
            if item_username:
                item.username = item_username
            if item_password:
                item.password = item_password

            item.save()
            messages.success(request, f'Item "{item.name}" updated successfully!')

        except VaultItem.DoesNotExist:
            messages.error(request, 'Item does not exist or you do not have permission to edit it')
        except NameExists:
            messages.error(request, 'Item with that name already exists')
        except Exception as e:
            messages.error(request, 'An error occurred while updating the item')

        return redirect('/vault/edit/')

    context = {
        "items": VaultItem.objects.filter(user=request.user),
    }
    return render(request, 'edit-dashboard.html', context=context)
