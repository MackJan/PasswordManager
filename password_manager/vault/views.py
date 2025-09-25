from django.shortcuts import render, redirect, get_object_or_404
from .models import VaultItem
from django.contrib import messages
from django.http import JsonResponse
from django.views.decorators.http import require_POST
from django.views.decorators.csrf import csrf_exempt
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
        action = request.POST.get('action', 'create')

        if action == 'create':
            # Handle item creation
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
            except Exception as e:
                logger.error(f"User {request.user.email} failed to create vault item {item_name} - error: {str(e)}")
                alerts_logger.error(f"Critical error in vault item creation for user {request.user.email}: {str(e)}")
                messages.error(request, 'Something went wrong!')

        elif action == 'edit':
            # Handle item editing
            item_name = request.POST.get('name')
            item_username = request.POST.get('username')
            item_password = request.POST.get('password')
            item_id = request.POST.get('id')

            logger.info(f"User {request.user.email} attempting to edit vault item ID: {item_id}")

            try:
                # Get the item and ensure it belongs to the current user
                item = get_object_or_404(VaultItem, id=item_id, user=request.user)
                old_name = item.name

                # Check for name conflicts (excluding current item)
                if item_name and item_name != old_name:
                    if VaultItem.objects.filter(name=item_name, user=request.user).exclude(id=item_id).exists():
                        logger.warning(f"User {request.user.email} tried to rename vault item to existing name: {item_name}")
                        messages.error(request, 'Item with that name already exists')
                        return redirect('/vault/')

                # Update fields
                if item_name:
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
            except Exception as e:
                logger.error(f"User {request.user.email} failed to update vault item ID {item_id} - error: {str(e)}")
                alerts_logger.error(f"Critical error in vault item update for user {request.user.email}: {str(e)}")
                messages.error(request, 'An error occurred while updating the item')

        elif action == 'delete':
            # Handle item deletion
            item_id = request.POST.get('id')
            logger.info(f"User {request.user.email} attempting to delete vault item ID: {item_id}")

            try:
                item = get_object_or_404(VaultItem, id=item_id, user=request.user)
                item_name = item.name
                item.delete()
                logger.info(f"User {request.user.email} successfully deleted vault item: {item_name}")
                messages.success(request, f'Item "{item_name}" deleted successfully!')
            except VaultItem.DoesNotExist:
                logger.error(f"User {request.user.email} tried to delete non-existent or unauthorized vault item ID: {item_id}")
                alerts_logger.error(f"Possible unauthorized access attempt by user {request.user.email} to vault item ID: {item_id}")
                messages.error(request, 'Item does not exist or you do not have permission to delete it')
            except Exception as e:
                logger.error(f"User {request.user.email} failed to delete vault item ID {item_id} - error: {str(e)}")
                alerts_logger.error(f"Critical error in vault item deletion for user {request.user.email}: {str(e)}")
                messages.error(request, 'An error occurred while deleting the item')

        return redirect('/vault/')

    context = {
        "items": VaultItem.objects.filter(user=request.user),
    }
    return render(request, 'dashboard.html', context=context)

def edit_dashboard(request):
    # Redirect to main dashboard since we're consolidating everything
    return redirect('/vault/')
