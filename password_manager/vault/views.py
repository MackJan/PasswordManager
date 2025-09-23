from django.shortcuts import render, redirect, get_object_or_404
from .models import VaultItem
from django.contrib import messages
import logging

# Get logger for vault app
logger = logging.getLogger('vault')
alerts_logger = logging.getLogger('alerts')

class NameExists(Exception):
    pass

# Create your views here.
def vault_dashboard(request):
    if not request.user.is_authenticated:
        logger.warning(f"Unauthorized vault access attempt from IP: {request.META.get('REMOTE_ADDR')}")
        return redirect('/login')

    logger.info(f"Vault dashboard accessed by user: {request.user.email}")

    if request.method == "POST":
        item_name = request.POST.get('name')
        item_username = request.POST.get('username')
        item_password = request.POST.get('password')

        logger.info(f"User {request.user.email} attempting to create vault item: {item_name}")

        if VaultItem.objects.filter(name=item_name, user=request.user).exists():
            logger.warning(f"User {request.user.email} tried to create duplicate vault item: {item_name}")
            messages.error(request, 'Item with that name already exists')
            return redirect('/vault/')
        try:
            item = VaultItem(name=item_name, username=item_username, password=item_password, user=request.user)
            item.save()
            logger.info(f"User {request.user.email} successfully created vault item: {item_name}")
            messages.success(request, f'Item "{item_name}" created successfully!')
        except NameExists:
            logger.warning(f"User {request.user.email} failed to create vault item {item_name} - name already exists")
            messages.error(request, f'Item "{item_name}" already exists!')
        except Exception as e:
            logger.error(f"User {request.user.email} failed to create vault item {item_name} - error: {str(e)}")
            alerts_logger.error(f"Critical error in vault item creation for user {request.user.email}: {str(e)}")
            messages.error(request, 'Something went wrong!')

    context = {
        "items": VaultItem.objects.filter(user=request.user),
    }
    return render(request, 'dashboard.html', context=context)

def edit_dashboard(request):
    if not request.user.is_authenticated:
        logger.warning(f"Unauthorized vault edit access attempt from IP: {request.META.get('REMOTE_ADDR')}")
        return redirect('/login')

    logger.info(f"Vault edit dashboard accessed by user: {request.user.email}")

    if request.method == "POST":
        item_name = request.POST.get('name')
        item_username = request.POST.get('username')
        item_password = request.POST.get('password')
        item_id = request.POST.get('id')

        logger.info(f"User {request.user.email} attempting to edit vault item ID: {item_id}")

        try:
            # Get the item and ensure it belongs to the current user
            item = get_object_or_404(VaultItem, id=item_id, user=request.user)
            old_name = item.name

            # Update fields only if they are provided
            if item_name:
                if VaultItem.objects.filter(name=item_name, user=request.user).exists():
                    logger.warning(f"User {request.user.email} tried to rename vault item to existing name: {item_name}")
                    raise NameExists()
                else:
                    item.name = item_name
            if item_username:
                item.username = item_username
            if item_password:
                item.password = item_password

            item.save()
            logger.info(f"User {request.user.email} successfully updated vault item: {old_name} -> {item.name}")
            messages.success(request, f'Item "{item.name}" updated successfully!')

        except VaultItem.DoesNotExist:
            logger.error(f"User {request.user.email} tried to edit non-existent or unauthorized vault item ID: {item_id}")
            alerts_logger.error(f"Possible unauthorized access attempt by user {request.user.email} to vault item ID: {item_id}")
            messages.error(request, 'Item does not exist or you do not have permission to edit it')
        except NameExists:
            logger.warning(f"User {request.user.email} failed to update vault item - name already exists: {item_name}")
            messages.error(request, 'Item with that name already exists')
        except Exception as e:
            logger.error(f"User {request.user.email} failed to update vault item ID {item_id} - error: {str(e)}")
            alerts_logger.error(f"Critical error in vault item update for user {request.user.email}: {str(e)}")
            messages.error(request, 'An error occurred while updating the item')

        return redirect('/vault/edit/')

    context = {
        "items": VaultItem.objects.filter(user=request.user),
    }
    return render(request, 'edit-dashboard.html', context=context)
