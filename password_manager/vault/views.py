from django.shortcuts import render, redirect, get_object_or_404
from django.contrib import messages
from django.http import JsonResponse
from .models import VaultItem
from .encryption_service import EncryptionService, VaultItemProxy
from .crypto_utils import CryptoError
import logging

# Get logger for vault app
logger = logging.getLogger('vault')
alerts_logger = logging.getLogger('alerts')

def _handle_create_item(request):
    """Handle creation of a new vault item."""
    item_name = request.POST.get('name')
    item_username = request.POST.get('username')
    item_password = request.POST.get('password')
    item_url = request.POST.get('url', '')
    item_notes = request.POST.get('notes', '')

    logger.info(f"User {request.user.email} attempting to create vault item.")

    if not item_name or not item_username or not item_password:
        messages.error(request, 'Name, username, and password are required')
        return

    try:
        # Prepare item data for encryption
        item_data = {
            'name': item_name,
            'username': item_username,
            'password': item_password,
            'url': item_url,
            'notes': item_notes
        }

        # Create encrypted vault item
        vault_item = EncryptionService.create_vault_item(request.user, item_data)

        logger.info(f"User {request.user.email} successfully created vault item {vault_item.id}.")
        messages.success(request, f'Item "{item_name}" created successfully!')

    except CryptoError as e:
        logger.error(f"Encryption error creating vault item for user {request.user.email}: {str(e)}")
        alerts_logger.error(f"Encryption error in vault item creation for user {request.user.email}: {str(e)}")
        messages.error(request, 'Encryption error occurred while creating the item')
    except Exception as e:
        logger.error(f"User {request.user.email} failed to create vault item - error: {str(e)}")
        alerts_logger.error(f"Critical error in vault item creation for user {request.user.email}: {str(e)}")
        messages.error(request, 'Something went wrong!')

def _handle_edit_item(request):
    """Handle editing of an existing vault item."""
    item_name = request.POST.get('name')
    item_username = request.POST.get('username')
    item_password = request.POST.get('password')
    item_url = request.POST.get('url', '')
    item_notes = request.POST.get('notes', '')
    item_id = request.POST.get('id')

    try:
        vault_item = get_object_or_404(VaultItem, id=item_id, user=request.user)

        logger.info(f"User {request.user.email} attempting to edit vault item {vault_item.id}.")

        if not item_name or not item_username or not item_password:
            messages.error(request, 'Name, username, and password are required')
            return

        # Prepare updated item data for encryption
        item_data = {
            'name': item_name,
            'username': item_username,
            'password': item_password,
            'url': item_url,
            'notes': item_notes
        }

        # Update encrypted vault item
        EncryptionService.update_vault_item(request.user, vault_item, item_data)

        logger.info(f"User {request.user.email} successfully updated vault item {vault_item.id}.")
        messages.success(request, f'Item "{item_name}" updated successfully!')

    except VaultItem.DoesNotExist:
        logger.error(f"User {request.user.email} tried to edit non-existent or unauthorized vault item.")
        alerts_logger.error(f"Possible unauthorized access attempt by user {request.user.email} to vault item.")
        messages.error(request, 'Item does not exist or you do not have permission to edit it')
    except CryptoError as e:
        logger.error(f"Encryption error updating vault item for user {request.user.email}: {str(e)}")
        alerts_logger.error(f"Encryption error in vault item update for user {request.user.email}: {str(e)}")
        messages.error(request, 'Encryption error occurred while updating the item')
    except Exception as e:
        logger.error(f"User {request.user.email} failed to update vault item - error: {str(e)}")
        alerts_logger.error(f"Critical error in vault item update for user {request.user.email}: {str(e)}")
        messages.error(request, 'An error occurred while updating the item')

def _handle_delete_item(request):
    """Handle deletion of a vault item."""
    item_id = request.POST.get('id')
    logger.info(f"User {request.user.email} attempting to delete vault item {item_id}.")

    try:
        vault_item = get_object_or_404(VaultItem, id=item_id, user=request.user)

        # Get display name for confirmation message
        display_name = vault_item.display_name or f"Item {str(vault_item.id)[:8]}"

        vault_item.delete()
        logger.info(f"User {request.user.email} successfully deleted vault item: {item_id}")
        messages.success(request, f'Item "{display_name}" deleted successfully!')

    except VaultItem.DoesNotExist:
        logger.error(f"User {request.user.email} tried to delete non-existent or unauthorized vault item {item_id}.")
        alerts_logger.error(f"Possible unauthorized access attempt by user {request.user.email} to vault item {item_id}.")
        messages.error(request, 'Item does not exist or you do not have permission to delete it')
    except Exception as e:
        logger.error(f"User {request.user.email} failed to delete vault item {item_id} - error: {str(e)}")
        alerts_logger.error(f"Critical error in vault item deletion for user {request.user.email}: {str(e)}")
        messages.error(request, 'An error occurred while deleting the item')

# Create your views here.
def vault_dashboard(request):
    if not request.user.is_authenticated:
        logger.warning(f"Unauthorized vault access attempt from IP: {request.META.get('REMOTE_ADDR')}")
        return redirect('/login')

    logger.info(f"Vault dashboard accessed by user: {request.user.email}")

    if request.method == "POST":
        action = request.POST.get('action', 'create')

        # Action handlers mapping
        action_handlers = {
            'create': _handle_create_item,
            'edit': _handle_edit_item,
            'delete': _handle_delete_item,
        }

        handler = action_handlers.get(action)
        if handler:
            handler(request)

        return redirect('/vault/')

    try:
        # Get vault items and create proxy objects for decryption
        vault_items = VaultItem.objects.filter(user=request.user)
        items = [VaultItemProxy(request.user, item) for item in vault_items]

        context = {
            "items": items,
        }

        # Set security headers for pages containing secrets
        response = render(request, 'dashboard.html', context=context)
        response['Cache-Control'] = 'no-store, private'
        response['Pragma'] = 'no-cache'

        return response

    except CryptoError as e:
        logger.error(f"Encryption error loading vault for user {request.user.email}: {str(e)}")
        alerts_logger.error(f"Encryption error in vault loading for user {request.user.email}: {str(e)}")
        messages.error(request, 'Unable to decrypt vault items. Please contact support.')
        return render(request, 'dashboard.html', {'items': []})
