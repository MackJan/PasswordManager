(function () {
  const overlay = document.querySelector('[data-modal-overlay]');
  const modals = new Map();
  const activeModals = [];

  document.querySelectorAll('[data-modal]').forEach((modal) => {
    modals.set(modal.dataset.modal, modal);
  });

  function trapFocus(modal) {
    const focusable = modal.querySelectorAll(
      'a[href], button:not([disabled]), textarea, input, select, [tabindex]:not([tabindex="-1"])'
    );
    if (!focusable.length) {
      return () => {};
    }
    const first = focusable[0];
    const last = focusable[focusable.length - 1];

    function handleKeydown(event) {
      if (event.key !== 'Tab') {
        return;
      }
      if (event.shiftKey && document.activeElement === first) {
        event.preventDefault();
        last.focus();
      } else if (!event.shiftKey && document.activeElement === last) {
        event.preventDefault();
        first.focus();
      }
    }

    modal.addEventListener('keydown', handleKeydown);
    return () => modal.removeEventListener('keydown', handleKeydown);
  }

  const focusStacks = new Map();

  function openModal(id) {
    const modal = modals.get(id);
    if (!modal) {
      return;
    }
    if (!activeModals.length) {
      overlay?.classList.add('is-active');
    }
    modal.classList.add('is-open');
    modal.setAttribute('aria-hidden', 'false');
    activeModals.push(modal);
    const release = trapFocus(modal);
    focusStacks.set(modal, release);
    const focusTarget = modal.querySelector('[data-initial-focus]') || modal.querySelector('input, button, textarea, select');
    window.setTimeout(() => focusTarget?.focus(), 20);
  }

  function closeModal(modal) {
    if (!modal) {
      return;
    }
    modal.classList.remove('is-open');
    modal.setAttribute('aria-hidden', 'true');
    const release = focusStacks.get(modal);
    release?.();
    focusStacks.delete(modal);
    const index = activeModals.indexOf(modal);
    if (index !== -1) {
      activeModals.splice(index, 1);
    }
    if (!activeModals.length) {
      overlay?.classList.remove('is-active');
    }
  }

  document.querySelectorAll('[data-modal-open]').forEach((trigger) => {
    trigger.addEventListener('click', () => {
      const target = trigger.dataset.modalOpen;
      if (!target) {
        return;
      }
      if (target === 'delete-item') {
        const modal = modals.get(target);
        if (modal) {
          const nameField = modal.querySelector('[data-delete-name]');
          const confirmBtn = modal.querySelector('[data-confirm-delete]');
          if (nameField) {
            nameField.textContent = trigger.dataset.itemName || '';
          }
          if (confirmBtn) {
            confirmBtn.dataset.formTarget = trigger.dataset.formId || '';
          }
        }
      }
      openModal(target);
    });
  });

  document.querySelectorAll('[data-modal-close]').forEach((button) => {
    button.addEventListener('click', () => {
      const modal = button.closest('[data-modal]');
      closeModal(modal);
    });
  });

  overlay?.addEventListener('click', () => {
    while (activeModals.length) {
      closeModal(activeModals.pop());
    }
  });

  document.addEventListener('keydown', (event) => {
    if (event.key === 'Escape' && activeModals.length) {
      closeModal(activeModals.pop());
    }
  });

  document.querySelectorAll('[data-confirm-delete]').forEach((button) => {
    button.addEventListener('click', () => {
      const formId = button.dataset.formTarget;
      if (!formId) {
        return;
      }
      const form = document.getElementById(formId);
      form?.submit();
      const modal = button.closest('[data-modal]');
      closeModal(modal);
    });
  });

  const passwordButtons = document.querySelectorAll('[data-toggle-password]');
  passwordButtons.forEach((button) => {
    button.addEventListener('click', () => {
      const targetId = button.dataset.togglePassword;
      const wrapper = document.getElementById(targetId);
      if (!wrapper) {
        return;
      }
      const isVisible = wrapper.dataset.visible === 'true';
      wrapper.dataset.visible = (!isVisible).toString();
      button.setAttribute('aria-pressed', (!isVisible).toString());
      const iconUse = button.querySelector('use');
      const label = button.querySelector('[data-toggle-label]');
      if (iconUse) {
        const eyeOn = button.dataset.eyeOn;
        const eyeOff = button.dataset.eyeOff;
        if (eyeOn && eyeOff) {
          iconUse.setAttribute('href', (!isVisible) ? eyeOff : eyeOn);
        }
      }
      if (label) {
        label.textContent = (!isVisible) ? 'Hide' : 'Reveal';
      }
    });
  });

  document.querySelectorAll('[data-copy]').forEach((button) => {
    button.addEventListener('click', async () => {
      const target = button.dataset.copy;
      const source = target ? document.getElementById(target) : null;
      const text = source?.innerText?.trim();
      if (!text) {
        showToast('Nothing to copy yet.', 'error');
        return;
      }
      try {
        await navigator.clipboard.writeText(text);
        button.classList.add('is-copied');
        showToast('Copied to clipboard.', 'success');
        window.setTimeout(() => button.classList.remove('is-copied'), 1500);
      } catch (error) {
        showToast('Copy failed. Try again.', 'error');
      }
    });
  });

  const filterInput = document.querySelector('[data-filter="vault"]');
  if (filterInput) {
    const rows = Array.from(document.querySelectorAll('[data-vault-row]'));
    rows.forEach((row) => {
      row.dataset.search = (row.dataset.search || '').toLowerCase();
    });
    filterInput.addEventListener('input', () => {
      const value = filterInput.value.trim().toLowerCase();
      rows.forEach((row) => {
        const haystack = row.dataset.search ?? '';
        row.style.display = haystack.includes(value) ? '' : 'none';
      });
    });
  }

  document.querySelectorAll('[data-action="print-recovery"]').forEach((button) => {
    button.addEventListener('click', () => window.print());
  });

  document.querySelectorAll('[data-download]').forEach((button) => {
    button.addEventListener('click', () => {
      const targetId = button.dataset.download;
      const filename = button.dataset.filename || 'download.txt';
      if (!targetId) {
        return;
      }
      const source = document.getElementById(targetId);
      const text = source?.innerText?.trim();
      if (!text) {
        showToast('Nothing to download yet.', 'error');
        return;
      }
      const blob = new Blob([text], { type: 'text/plain' });
      const url = URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.download = filename;
      document.body.appendChild(link);
      link.click();
      link.remove();
      URL.revokeObjectURL(url);
      showToast('Download started.', 'success');
    });
  });

  document.querySelectorAll('[data-confirm-toggle]').forEach((checkbox) => {
    const targetId = checkbox.dataset.confirmToggle;
    const target = targetId ? document.getElementById(targetId) : null;
    const update = () => {
      if (!target) {
        return;
      }
      const enabled = checkbox.checked;
      target.disabled = !enabled;
      target.classList.toggle('is-disabled', !enabled);
      if (enabled) {
        target.removeAttribute('aria-disabled');
      } else {
        target.setAttribute('aria-disabled', 'true');
      }
    };
    checkbox.addEventListener('change', update);
    update();
  });

  document.querySelectorAll('[data-redirect]').forEach((button) => {
    button.addEventListener('click', () => {
      if (button.disabled) {
        return;
      }
      const url = button.dataset.redirect;
      if (url) {
        window.location.assign(url);
      }
    });
  });

  document.querySelectorAll('[data-format="recovery"]').forEach((input) => {
    input.addEventListener('input', () => {
      const raw = input.value.replace(/[^A-Za-z0-9]/g, '').slice(0, 8);
      if (raw.length > 4) {
        input.value = `${raw.slice(0, 4)}-${raw.slice(4)}`;
      } else {
        input.value = raw;
      }
    });
  });

  function showToast(message, variant = 'info') {
    const stack = document.querySelector('[data-toast-stack]');
    if (!stack) {
      return;
    }
    const toast = document.createElement('div');
    toast.className = 'toast';
    toast.dataset.variant = variant;
    toast.innerHTML = `
      <div class="toast-message">${message}</div>
      <button class="toast-dismiss" type="button" aria-label="Dismiss">&times;</button>
    `;
    stack.appendChild(toast);
    const dismiss = toast.querySelector('.toast-dismiss');
    dismiss.addEventListener('click', () => {
      toast.remove();
    });
    window.setTimeout(() => {
      toast.classList.add('is-hiding');
      toast.addEventListener('transitionend', () => toast.remove(), { once: true });
    }, 4000);
  }

  document.querySelectorAll('[data-message]').forEach((message) => {
    const text = message.textContent.trim();
    if (!text) {
      return;
    }
    const level = message.dataset.level || 'info';
    showToast(text, level.includes('error') || level.includes('danger') ? 'error' : level.includes('success') ? 'success' : 'info');
  });
})();
