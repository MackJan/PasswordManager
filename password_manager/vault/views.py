from django.shortcuts import render, redirect, get_object_or_404
from django.contrib import messages
from .models import VaultItem
from .encryption_service import EncryptionService, VaultItemProxy
from vault.exceptions import CryptoError
from core.logging_utils import get_vault_logger
from core.middleware import get_client_ip
import logging

# Get centralized logger
logger = get_vault_logger()

def _handle_create_item(request):
    """Handle creation of a new vault item."""
    item_name = request.POST.get('name')
    item_username = request.POST.get('username')
    item_password = request.POST.get('password')
    item_url = request.POST.get('url', '')
    item_notes = request.POST.get('notes', '')

    logger.user_activity("vault_item_creation_attempt", request.user, "Creating new vault item")

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

        logger.user_activity("vault_item_created", request.user, f"Successfully created vault item {vault_item.id}")
        messages.success(request, f'Item "{item_name}" created successfully!')

    except CryptoError as e:
        logger.encryption_event(f"vault item creation failed: {str(e)}", request.user, success=False)
        logger.critical("Encryption error in vault item creation", request.user)
        messages.error(request, 'Encryption error occurred while creating the item')
    except Exception as e:
        logger.error("Vault item creation failed", request.user, extra_data={"error": str(e)})
        logger.critical("Critical error in vault item creation", request.user)
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

        logger.user_activity("vault_item_edit_attempt", request.user, f"Editing vault item {vault_item.id}")

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

        logger.user_activity("vault_item_updated", request.user, f"Successfully updated vault item {vault_item.id}")
        messages.success(request, f'Item "{item_name}" updated successfully!')

    except VaultItem.DoesNotExist:
        logger.security_event("Unauthorized vault item edit attempt", request.user, extra_data={"item_id": item_id})
        logger.critical("Possible unauthorized access attempt to vault item", request.user)
        messages.error(request, 'Item does not exist or you do not have permission to edit it')
    except CryptoError as e:
        logger.encryption_event(f"vault item update failed: {str(e)}", request.user, success=False)
        logger.critical("Encryption error in vault item update", request.user)
        messages.error(request, 'Encryption error occurred while updating the item')
    except Exception as e:
        logger.error("Vault item update failed", request.user, extra_data={"error": str(e), "item_id": item_id})
        logger.critical("Critical error in vault item update", request.user)
        messages.error(request, 'An error occurred while updating the item')

def _handle_delete_item(request):
    """Handle deletion of a vault item."""
    item_id = request.POST.get('id')
    logger.user_activity("vault_item_delete_attempt", request.user, f"Attempting to delete vault item {item_id}")

    try:
        vault_item = get_object_or_404(VaultItem, id=item_id, user=request.user)

        # Get display name for confirmation message
        display_name = vault_item.display_name or f"Item {str(vault_item.id)[:8]}"

        vault_item.delete()
        logger.user_activity("vault_item_deleted", request.user, f"Successfully deleted vault item: {item_id}")
        messages.success(request, f'Item "{display_name}" deleted successfully!')

    except VaultItem.DoesNotExist:
        logger.security_event("Unauthorized vault item delete attempt", request.user, extra_data={"item_id": item_id})
        logger.critical("Possible unauthorized access attempt to vault item", request.user)
        messages.error(request, 'Item does not exist or you do not have permission to delete it')
    except Exception as e:
        logger.error("Vault item deletion failed", request.user, extra_data={"error": str(e), "item_id": item_id})
        logger.critical("Critical error in vault item deletion", request.user)
        messages.error(request, 'An error occurred while deleting the item')

# Create your views here.
def vault_dashboard(request):
    if not request.user.is_authenticated:
        logger.warning(f"Unauthorized vault access attempt from IP: {get_client_ip(request)}")
        return redirect('/login')

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
        logger.encryption_event(f"vault loading failed: {str(e)}", request.user, success=False)
        logger.critical("Encryption error in vault loading", request.user)
        messages.error(request, 'Unable to decrypt vault items. Please contact support.')
        return render(request, 'dashboard.html', {'items': []})
