# Password Manager - Project Report

**Course:** Web Application Security (ICS0020)  
**Project:** Secure Password Manager Web Application  
**Date:** November 22, 2025

---

## Executive Summary

This project implements a production-ready, web-based password manager built with the python framework Django, focusing on secure credential storage, robust encryption, and protection against common web vulnerabilities. The application employs a three-tier encryption hierarchy (AMK → UMK → DEK), AES-256-GCM authenticated encryption, Argon2 password hashing, and comprehensive security measures including CSRF protection, SQL injection prevention, XSS mitigation, and optional two-factor authentication.

**Deployment:** Currently hosted at [https://password.janmack.de](https://password.janmack.de)

---

## 1. Project Architecture

### 1.1 Technology Stack

| Component             | Technology              |
|-----------------------|-------------------------|
| **Backend Framework** | Django                  |
| **Database**          | PostgreSQL              |
| **Password Hashing**  | Argon2                  |
| **Encryption**        | AES-256-GCM             |
| **Authentication**    | django-allauth          |
| **Containerization**  | Docker & Docker Compose |
| **Monitoring**        | Grafana, Loki, Promtail |
| **Static Analysis**   | SonarCloud              |
| **Web Server**        | Gunicorn + WhiteNoise   |

### 1.2 File Structure

```
PasswordManager/
├── password_manager/           # Main Django project
│   ├── accounts/              # User authentication & management
│   │   ├── models.py          # CustomUser, UserKeystore
│   │   ├── views.py           # 2FA, profile, recovery codes
│   │   ├── adapter.py         # Custom allauth adapter
│   │   ├── mfa_adapter.py     # MFA customization
│   │   ├── signals.py         # Auth event logging
│   │   └── recovery.py        # Recovery code handling
│   ├── vault/                 # Password vault functionality
│   │   ├── models.py          # VaultItem model
│   │   ├── views.py           # CRUD operations
│   │   ├── crypto_utils.py    # Low-level encryption primitives
│   │   ├── encryption_service.py  # High-level encryption service
│   │   ├── fields.py          # Legacy encrypted fields
│   │   └── tests.py           # Comprehensive test suite
│   ├── core/                  # Core utilities
│   │   ├── middleware.py      # Rate limiting, logging, IP detection
│   │   ├── rate_limit.py      # Rate limiting utilities
│   │   ├── logging_utils.py   # Centralized logging
│   │   └── views.py           # Home page
│   ├── password_manager/      # Project settings
│   │   ├── settings.py        # Django configuration
│   │   └── urls.py            # URL routing
│   ├── templates/             # HTML templates
│   │   ├── account/           # Authentication templates
│   │   ├── accounts/          # Profile templates
│   │   └── mfa/               # 2FA templates
│   ├── .keys/                 # AMK storage (restricted permissions)
│   └── logs/                  # Application logs
├── docs/
│   └── encryption_overview.md # Detailed encryption documentation
├── docker-compose.yaml        # Container orchestration
├── grafana-dashboard.json     # Monitoring dashboard config
└── README.md                  # Setup instructions
```

---

## 2. Security Implementation

### 2.1 Secure Credential Storage

#### Encryption Hierarchy

The application implements a **three-tier key hierarchy**:

1. **Application Master Key (AMK)** - 32-byte root key
   - **Storage:** `.keys/amk.key` file OR `AMK_V1` environment variable (in production)
   - **Purpose:** Wraps all User Master Keys
   - **Implementation:** `vault/crypto_utils.py` (AMKManager class, lines 25-142)
   - **Rotation:** Supports versioned key rotation

2. **User Master Key (UMK)** - 32-byte per-user key
   - **Generation:** Created during user registration
   - **Storage:** Encrypted with AMK in `accounts_userkeystore` table
   - **Fields:** `wrapped_umk_b64`, `umk_nonce_b64`, `amk_key_version`, `algo_version`
   - **Implementation:** `accounts/models.py` (UserKeystore model, lines 46-65)

3. **Data Encryption Key (DEK)** - 32-byte per-item key
   - **Generation:** New DEK for each vault item creation/update
   - **Storage:** Encrypted with UMK in `vault_vaultitem` table
   - **Fields:** `wrapped_dek_b64`, `dek_wrap_nonce_b64`
   - **Purpose:** Encrypts actual password data

4. **Item Salt** - 16-byte random salt per item
   - **Purpose:** Derives unique AEAD key via HKDF-SHA256
   - **Storage:** `item_salt_b64` field
   - **Benefit:** Ensures unique ciphertexts even for identical data

#### Encryption Algorithm

**AES-256-GCM (Authenticated Encryption with Associated Data)**

- **Mode:** Galois/Counter Mode (AEAD)
- **Key Size:** 256 bits (32 bytes)
- **Nonce Size:** 96 bits (12 bytes)
- **Benefits:**
  - Confidentiality (encryption)
  - Integrity (authentication tag)
  - Authenticity (prevents tampering)
- **Implementation:** `vault/crypto_utils.py` (lines 181-233)

#### Additional Authenticated Data (AAD)

Each encryption operation includes context-specific AAD:

```python
# UMK wrapping: {user_id, algo_version, amk_version}
# DEK wrapping: {user_id: 0, item_id, algo_version}
# Item data: {user_id, item_id, algo_version}
```

**Purpose:** Binds ciphertext to specific context, preventing ciphertext reuse attacks.

#### Data Flow Example

```
User Registration:
1. Generate UMK (32 random bytes)
2. Wrap UMK with AMK using AES-256-GCM
3. Store wrapped_umk_b64, nonce, version in UserKeystore

Creating Password Entry:
1. Retrieve and unwrap UMK using AMK
2. Generate DEK (32 random bytes)
3. Generate item salt (16 random bytes)
4. Derive item key: HKDF(DEK, salt)
5. Encrypt item data with derived key
6. Wrap DEK with UMK
7. Store all encrypted data in VaultItem
8. Securely zero UMK and DEK from memory
```

**Implementation:** `vault/encryption_service.py` (EncryptionService class)

#### TLS/HTTPS

- **Production:** Enforced via `SECURE_SSL_REDIRECT = True`
- **Headers:** HSTS with 1-year max-age, includeSubDomains, preload
- **Settings:** `password_manager/settings.py` (lines 62-74)

---

### 2.2 Master Password and Authentication

#### Password Hashing
Mostly implemented by django allauth.

**Argon2id** - Memory-hard password hashing algorithm

```python
PASSWORD_HASHERS = [
    'django.contrib.auth.hashers.Argon2PasswordHasher',  # Primary
    'django.contrib.auth.hashers.PBKDF2PasswordHasher',
    'django.contrib.auth.hashers.PBKDF2SHA1PasswordHasher',
    'django.contrib.auth.hashers.BCryptSHA256PasswordHasher',
]
```

**Configuration:** `settings.py` (lines 172-177)

#### Password Validation

Django's built-in validators enforce strong passwords:

```python
AUTH_PASSWORD_VALIDATORS = [
    'UserAttributeSimilarityValidator',  # Prevents user info in password
    'MinimumLengthValidator',            # Minimum 8 characters
    'CommonPasswordValidator',           # Blocks common passwords
    'NumericPasswordValidator',          # Prevents all-numeric passwords
]
```

**Configuration:** `settings.py` (lines 156-169)

#### Multi-Factor Authentication (MFA/2FA)

**Implementation:** TOTP (Time-based One-Time Password) via `django-allauth[mfa]`

**Features:**
- QR code generation for authenticator apps (Google Authenticator, Authy)
- 6-digit codes, 30-second validity window
- 10 recovery codes per user
- Recovery code regeneration
- Custom MFA adapter for enhanced security

**Files:**
- `accounts/views.py` - enable_2fa(), disable_2fa(), recovery_code_login()
- `accounts/mfa_adapter.py` - CustomMFAAdapter
- `accounts/recovery.py` - Recovery code management

**Configuration:** `settings.py` (lines 442-447)

```python
MFA_ADAPTER = 'accounts.mfa_adapter.CustomMFAAdapter'
MFA_TOTP_PERIOD = 30
MFA_TOTP_DIGITS = 6
MFA_RECOVERY_CODE_COUNT = 10
MFA_SUPPORTED_TYPES = ['totp', 'recovery_codes']
```

#### Session Security

**Secure Cookie Settings:**

```python
SESSION_COOKIE_SECURE = True      # HTTPS only
SESSION_COOKIE_HTTPONLY = True    # No JavaScript access
SESSION_COOKIE_SAMESITE = 'Strict'  # CSRF protection
CSRF_COOKIE_SECURE = True
CSRF_COOKIE_HTTPONLY = True
CSRF_COOKIE_SAMESITE = 'Strict'
```

**Configuration:** `settings.py` (lines 64-69)

**Session Management:**
- Django's built-in session framework
- Database-backed sessions (PostgreSQL)
- Automatic session expiration
- Logout on password change

---

### 2.3 SQL Injection Prevention

**Django ORM Protection**

**Django's ORM automatically uses **parameterized queries** for all database operations, preventing SQL injection by design.**

#### Example from VaultItem Model

```python
# Safe - Django ORM automatically parameterizes
vault_items = VaultItem.objects.filter(user=request.user)
vault_item = get_object_or_404(VaultItem, id=item_id, user=request.user)
```

**Implementation:** `vault/views.py` (lines 123-164)

#### How Django Prevents SQL Injection

1. **Query Parameterization:** All user inputs are passed as parameters, not concatenated into SQL strings
2. **Type Validation:** Model fields enforce type constraints
3. **Escaping:** Database adapter handles proper escaping
4. **No Raw SQL:** Application avoids raw SQL queries

#### Database Configuration

```python
DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.postgresql",
        "NAME": os.environ.get("SQL_DATABASE"),
        "USER": os.environ.get("SQL_USER"),
        "PASSWORD": os.environ.get("SQL_PASSWORD"),
        "HOST": os.environ.get("SQL_HOST"),
        "PORT": os.environ.get("SQL_PORT"),
    }
}
```

**PostgreSQL Benefits:**
- Strong type system
- ACID compliance
- Prepared statement support
- Row-level security capabilities

---

### 2.4 Cross-Site Scripting (XSS) Prevention

#### Django Template Auto-Escaping

Django templates automatically escape all variables by default:

```django
{{ item.name }}  <!-- Automatically HTML-escaped -->
{{ item.username|escape }}  <!-- Explicit escaping -->
```

**How It Works:**
- Converts `<` to `&lt;`, `>` to `&gt;`, `&` to `&amp;`, etc.
- Prevents JavaScript injection
- Enabled by default in all templates

#### Content Security Policy (CSP)

**Headers Set:**

```python
SECURE_CONTENT_TYPE_NOSNIFF = True
SECURE_REFERRER_POLICY = 'same-origin'
```

**Configuration:** `settings.py` (lines 73-74)

#### Input Validation

All user inputs are validated through Django forms and model validation:

```python
# Example from vault item creation
if not item_name or not item_username or not item_password:
    messages.error(request, 'Name, username, and password are required')
    return
```

**Implementation:** `vault/views.py` (lines 13-50)

#### Output Encoding

- **JSON Serialization:** Uses `json.dumps()` with proper escaping
- **URL Encoding:** Django's `urlencode()` for query parameters
- **JavaScript Context:** Avoids inline JavaScript; uses data attributes

---

### 2.5 CSRF Protection

#### Django's Built-in CSRF Middleware

**Enabled:** `django.middleware.csrf.CsrfViewMiddleware`

**Configuration:** `settings.py` (line 102)

#### How It Works

1. **Token Generation:** Unique token per session
2. **Template Tag:** `{% csrf_token %}` in all forms
3. **Validation:** Middleware validates token on POST requests
4. **Rejection:** Invalid/missing tokens return 403 Forbidden

#### Example Form Protection

```django
<form method="POST" action="/vault/">
    {% csrf_token %}
    <input type="text" name="name" required>
    <input type="password" name="password" required>
    <button type="submit">Save</button>
</form>
```

#### AJAX Protection

For AJAX requests, CSRF token is included in headers:

```javascript
fetch('/api/endpoint/', {
    method: 'POST',
    headers: {
        'X-CSRFToken': getCookie('csrftoken'),
        'Content-Type': 'application/json'
    },
    body: JSON.stringify(data)
});
```

#### Cookie Security

```python
CSRF_COOKIE_SECURE = True      # HTTPS only
CSRF_COOKIE_HTTPONLY = True    # No JavaScript access
CSRF_COOKIE_SAMESITE = 'Strict'
CSRF_TRUSTED_ORIGINS = [...]   # Whitelisted origins
```

---

### 2.6 Access Control

#### Per-User Ownership Enforcement

**Every database query enforces user ownership:**

```python
# Vault views always filter by current user
vault_items = VaultItem.objects.filter(user=request.user)

# Edit/Delete operations verify ownership
vault_item = get_object_or_404(VaultItem, id=item_id, user=request.user)
```

**Implementation:** `vault/views.py`

#### Authentication Requirements

**Login Required Decorator:**

```python
@login_required
def profile_view(request):
    # Only authenticated users can access
    ...
```

**Manual Checks:**

```python
def vault_dashboard(request):
    if not request.user.is_authenticated:
        logger.warning(f"Unauthorized vault access attempt from IP: {get_client_ip(request)}")
        return redirect('/login')
```

**Implementation:** `vault/views.py` (lines 123-125)

#### Database-Level Constraints

```python
class VaultItem(models.Model):
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,  # Delete items when user deleted
        related_name='vault_items'
    )
```

**Foreign Key Constraint:** Ensures items always belong to valid user

#### Security Event Logging

Unauthorized access attempts are logged:

```python
logger.security_event(
    "Unauthorized vault item edit attempt",
    request.user,
    extra_data={"item_id": item_id}
)
logger.critical("Possible unauthorized access attempt to vault item", request.user)
```

**Implementation:** `vault/views.py` (lines 86-88)

---

### 2.7 Error Handling & Logging

#### Generic User-Facing Errors

**No Stack Traces or Internals Exposed:**

```python
try:
    vault_item = EncryptionService.create_vault_item(request.user, item_data)
    messages.success(request, f'Item "{item_name}" created successfully!')
except CryptoError as e:
    logger.encryption_event(f"vault item creation failed: {str(e)}", request.user, success=False)
    logger.critical("Encryption error in vault item creation", request.user)
    messages.error(request, 'Encryption error occurred while creating the item')  # Generic message
except Exception as e:
    logger.error("Vault item creation failed", request.user, extra_data={"error": str(e)})
    messages.error(request, 'Something went wrong!')  # Generic message
```

**Implementation:** `vault/views.py` (lines 42-50)

#### Comprehensive Logging System

**Structured JSON Logging:**

```python
LOGGING = {
    'formatters': {
        'json': {
            '()': 'core.logging_formatters.StructuredJSONFormatter',
        },
    },
    'handlers': {
        'application_file': {...},  # General app logs
        'auth_file': {...},         # Authentication events
        'vault_file': {...},        # Vault operations
        'security_file': {...},     # Security events
        'alerts_file': {...},       # Critical alerts
        'django_file': {...},       # Django framework logs
    },
}
```

**Configuration:** `settings.py` (lines 269-410)

#### Centralized Logging Utilities

**AppLogger Class:**

```python
logger = get_vault_logger()

logger.user_activity("vault_item_created", request.user, f"Successfully created vault item {vault_item.id}")
logger.security_event("Unauthorized vault item delete attempt", request.user, extra_data={"item_id": item_id})
logger.encryption_event("vault item creation failed", request.user, success=False)
logger.critical("Critical error in vault item creation", request.user)
```

**Implementation:** `core/logging_utils.py`

#### Log Aggregation & Monitoring

**Grafana + Loki + Promtail Stack:**

- **Loki:** Aggregates logs from all services
- **Promtail:** Ships logs from Django application
- **Grafana:** Visualizes logs with pre-configured dashboard and alerts
- **Access:** http://localhost:3000 (admin/test_password!)

**Configuration:** `docker-compose.yaml`, `loki-config.yaml`, `promtail-config.yaml`

#### Debug Mode Disabled in Production

```python
DEBUG = False  # Never True in production
```

**Configuration:** `settings.py` (line 30)

---

### 2.8 Additional Security Features

#### Rate Limiting

**Custom Rate Limiting Middleware:**

```python
class RateLimitMiddleware:
    LOGIN_PATH_PREFIX = "/accounts/login"
    PASSWORD_RESET_PATH_PREFIX = "/accounts/password/reset"
    MALICIOUS_PATTERNS = (".env", "wp-admin", "phpMyAdmin", ...)
```

**Scenarios:**
- **Login Attempts:** 10 attempts per IP / 6 per email in 10 minutes → 30-minute block
- **Password Reset:** 3 attempts per IP / 3 per email in 15 minutes → 1-hour block
- **Recovery Codes:** 5 attempts per IP / 3 per email in 15 minutes → 1-hour block
- **Malicious Traffic:** Instant block for suspicious paths

**Implementation:** `core/middleware.py` (lines 187-331), `core/rate_limit.py`

#### Security Headers

```python
SECURE_HSTS_SECONDS = 31536000  # 1 year
SECURE_HSTS_INCLUDE_SUBDOMAINS = True
SECURE_HSTS_PRELOAD = True
SECURE_CONTENT_TYPE_NOSNIFF = True
SECURE_REFERRER_POLICY = 'same-origin'
X_FRAME_OPTIONS = 'DENY'  # Clickjacking protection
```

**Configuration:** `settings.py` (lines 70-74)

#### Trusted Proxy Configuration

```python
TRUSTED_PROXY_IPS = _parse_trusted_proxies(os.environ.get("TRUSTED_PROXY_IPS", ""))
SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")
```

**Purpose:** Correctly identify client IPs behind reverse proxies

**Implementation:** `settings.py` (lines 49-76), `core/middleware.py` (lines 19-117)

#### Cache-Control for Sensitive Pages

```python
response['Cache-Control'] = 'no-store, private'
response['Pragma'] = 'no-cache'
```

**Purpose:** Prevents browser/proxy caching of password data

**Implementation:** `vault/views.py` (lines 158-159)

---

## 3. Application Workflow

### 3.1 User Registration Flow

```
1. User submits email + password via /accounts/signup/
2. Django validates password strength (Argon2 validators)
3. CustomAccountAdapter.save_user() triggered
4. EncryptionService.setup_user_encryption():
   a. Generate 32-byte UMK
   b. Wrap UMK with AMK using AES-256-GCM
   c. Store wrapped UMK in UserKeystore
5. Email confirmation sent (mandatory)
6. User confirms email via link
7. Account activated, user can login
```

**Implementation:**
- `accounts/adapter.py` (lines 6-44)
- `vault/encryption_service.py` (lines 25-73)

### 3.2 Login Flow

```
1. User submits email + password
2. Argon2 verifies password hash
3. Rate limiting checked (10 attempts/10min per IP)
4. If 2FA enabled:
   a. Prompt for TOTP code
   b. Validate against stored secret
   c. OR accept recovery code
5. Session created with secure cookies
6. Rate limits reset on success
7. Redirect to /home/ or /vault/
```

**Implementation:**
- `accounts/signals.py` (lines 23-69)
- `accounts/views.py` (recovery_code_login, lines 220-357)

### 3.3 Creating Password Entry

```
1. User submits form with name, username, password, URL, notes
2. vault_dashboard() receives POST request
3. _handle_create_item() validates required fields
4. EncryptionService.create_vault_item():
   a. Ensure user keystore exists
   b. Unwrap UMK from keystore using AMK
   c. Generate new 32-byte DEK
   d. Generate 16-byte item salt
   e. Create placeholder VaultItem (get UUID)
   f. Derive item key: HKDF(DEK, salt)
   g. Encrypt item data with derived key + AAD
   h. Wrap DEK with UMK + AAD
   i. Store wrapped_dek, ciphertext, salt, nonces
   j. Securely zero UMK and DEK from memory
5. Success message shown to user
6. Redirect to /vault/
```

**Implementation:**
- `vault/views.py` (lines 13-50, 123-164)
- `vault/encryption_service.py` (lines 125-207)

### 3.4 Viewing Password Entry

```
1. User navigates to /vault/
2. vault_dashboard() retrieves VaultItem.objects.filter(user=request.user)
3. For each item, create VaultItemProxy:
   a. Lazy decryption on first property access
   b. Unwrap UMK using AMK
   c. Unwrap DEK using UMK
   d. Derive item key from DEK + salt
   e. Decrypt item data with derived key
   f. Cache decrypted data for request lifecycle
4. Render dashboard.html with decrypted items
5. Set Cache-Control: no-store headers
```

**Implementation:**
- `vault/views.py` (lines 148-164)
- `vault/encryption_service.py` (VaultItemProxy, lines 434-487)

### 3.5 Updating Password Entry

```
1. User submits edit form with item ID
2. _handle_edit_item() validates ownership
3. EncryptionService.update_vault_item():
   a. Generate NEW DEK (forward secrecy)
   b. Generate NEW salt
   c. Encrypt updated data with new DEK
   d. Wrap new DEK with UMK
   e. Update VaultItem with new ciphertext
   f. Securely zero keys
4. Success message shown
```

**Implementation:**
- `vault/views.py` (lines 52-96)
- `vault/encryption_service.py` (lines 349-405)

### 3.6 Deleting Password Entry

```
1. User clicks delete button
2. _handle_delete_item() validates ownership
3. VaultItem.delete() called
4. Database cascade deletes item
5. Success message shown
```

**Implementation:**
- `vault/views.py` (lines 98-120)

---

## 4. Testing

### 4.1 Test Coverage

**Test Files:**
- `vault/tests.py` - 522 lines, 18 test classes/functions
- `accounts/tests.py` - Authentication tests
- `core/tests.py` - Middleware and utility tests

### 4.2 Test Categories

#### Cryptographic Tests

```python
class CryptoUtilsTests(SimpleTestCase):
    def test_wrap_and_unwrap_umk_round_trip(self)
    def test_wrap_and_unwrap_dek_round_trip(self)
    def test_encrypt_and_decrypt_item_data_round_trip(self)
    def test_aead_decrypt_raises_on_tampered_ciphertext(self)
    def test_derive_item_key_requires_salt(self)
```

**Purpose:** Verify encryption/decryption correctness and tamper detection

#### Service Layer Tests

```python
class EncryptionServiceTests(TestCase):
    def test_create_vault_item_persists_encrypted_fields(self)
    def test_decrypt_vault_item_falls_back_to_legacy_strategy(self)
    def test_vault_item_proxy_caches_decrypted_data(self)
```

**Purpose:** Test high-level encryption workflows

#### View Tests

```python
class VaultViewsTests(TestCase):
    def test_handle_create_item_validates_required_fields(self)
    def test_handle_edit_item_missing_object_logs_security_event(self)
    def test_vault_dashboard_redirects_anonymous_users(self)
    def test_vault_dashboard_get_success_sets_secure_headers(self)
```

**Purpose:** Verify access control, validation, and security logging

### 4.3 Running Tests

```bash
# Run all tests
docker compose exec web python manage.py test

# Run specific app tests
docker compose exec web python manage.py test vault
docker compose exec web python manage.py test accounts

# Run with coverage
docker compose exec web coverage run --source='.' manage.py test
docker compose exec web coverage report
```

---

## 5. Local Deployment & Operations

### 5.1 Docker Setup

**Services:**
- **web:** Django application (port 8000)
- **db:** PostgreSQL 15 (port 5432)
- **grafana:** Monitoring dashboard (port 3000)
- **loki:** Log aggregation (port 3100)
- **promtail:** Log shipping agent

**Configuration:** `docker-compose.yaml`

### 5.2 Environment Variables

**Required:**
```bash
SECRET_KEY='strong-random-secret-key'
DJANGO_ALLOWED_HOSTS='localhost 127.0.0.1'
SQL_ENGINE='django.db.backends.postgresql'
SQL_DATABASE='django_dev'
SQL_USER='django'
SQL_PASSWORD='django'
SQL_HOST='db'
SQL_PORT='5432'
AMK_V1='base64-encoded-32-byte-key'  # required for production only
```

**Optional:**
```bash
DEBUG=0
SECURE_SSL_REDIRECT=1
SESSION_COOKIE_SECURE=1
CSRF_COOKIE_SECURE=1
EMAIL_BACKEND='django.core.mail.backends.smtp.EmailBackend'
EMAIL_HOST='smtp.example.com'
EMAIL_PORT=587
```

### 5.3 Deployment Steps

```bash
# 1. Clone repository
git clone https://github.com/MackJan/PasswordManager.git
cd PasswordManager

# 2. Create environment file
cp .env.dev.example .env.dev
# Edit .env.dev with required values

# 3. Build and start containers
docker compose up --build -d

# 4. Run migrations
docker compose exec web python manage.py migrate

# 5. Create superuser
docker compose exec web python manage.py createsuperuser
# this account will have access to the /admin page

# 6. Collect static files
docker compose exec web python manage.py collectstatic --noinput

# 7. Access application
# Web: http://localhost:8000
# Admin: http://localhost:8000/admin/
# Grafana: http://localhost:3000
```

### 5.3.1 Loki setup
```bash
# Access Grafana at http://localhost:3000 (admin/test_password!)
# Add Loki data source:
# URL: http://loki:3100
# Import dashboard from grafana-dashboard.json
```

### 5.4 Production Considerations

**AMK Management:**
```bash
# Generate AMK
python manage.py manage_amk generate

# Backup AMK
cp password_manager/.keys/amk.key /secure/backup/location/

# Use environment variable in production
export AMK_V1=$(cat .keys/amk.key | jq -r '.["1"]')
```

**Database Backups:**
```bash
# Backup
docker compose exec db pg_dump -U django django_dev > backup.sql

# Restore
docker compose exec -T db psql -U django django_dev < backup.sql
```

**Log Rotation:**
- Configured via `RotatingFileHandler`
- Max size: 10 MB per file
- Backup count: 5 files
- Automatic rotation


### 5.5 Production Deployment

The application's code is hosted on [GitHub](https://github.com/MackJan/PasswordManager) with automated CI/CD pipelines.

#### 5.5.1 CI/CD Pipeline Implementation

**Deployment Action**: GitHub Actions workflow triggers on push to `main` branch

- Builds production Docker image
- Pushes to GitHub Container Registry (ghcr.io)
- Self-hosted runner connects to production server via SSH
- Copies environment variables from GitHub Actions secrets
- Pulls latest image and restarts web container
- Database remains persistent across deployments

**SonarCloud Action**: Static code analysis on every push to `main` branch and pull requests

- Runs SonarCloud scan for code quality metrics
- Reports vulnerabilities, code smells, and technical debt
- View analysis at [SonarCloud Dashboard](https://sonarcloud.io/dashboard?id=MackJan_PasswordManager)

#### 5.5.2 Production Infrastructure

**Architecture Overview:**

```
Internet
    ↓
[Firewall] (UFW) - Only ports 80, 443, 22 open
    ↓
[Nginx Reverse Proxy] - SSL termination, request routing
    ↓
    ├─→ password.janmack.de → Django (localhost:8000)
    └─→ grafana.janmack.de → Grafana (localhost:3000)
    ↓
[Docker Compose Stack]
    ├─ web (Django) - Internal only (127.0.0.1:8000)
    ├─ db (PostgreSQL) - No external exposure
    ├─ grafana - Internal only (127.0.0.1:3000)
    ├─ loki - Internal only (127.0.0.1:3100)
    └─ promtail - Log collector
```

**Docker Compose Configuration:**

```yaml
services:
  web:
    image: ${DJANGO_IMAGE}
    ports:
      - "127.0.0.1:8000:8000"  # Localhost binding only
    networks:
      - webnet
      - monitoring
    restart: unless-stopped
    
  db:
    image: postgres:15
    # No port exposure - internal network only
    networks:
      - webnet
    restart: unless-stopped
    
  grafana:
    ports:
      - "127.0.0.1:3000:3000"  # Localhost binding only
    networks:
      - monitoring
```

**Key Security Features:**

- **Port Binding:** All services bound to `127.0.0.1` (localhost only)
- **Network Isolation:** Separate Docker networks (`webnet`, `monitoring`)
- **No Direct Access:** Database has no exposed ports
- **Reverse Proxy Only:** Public access exclusively through Nginx

#### 5.5.3 SSL Certificate Management

**Let's Encrypt with Certbot:**

**Certificate Details:**

- **Issuer:** Let's Encrypt Authority X3
- **Validity:** 90 days (auto-renewed at 30 days)
- **Protocol Support:** TLSv1.2, TLSv1.3
- **Key Type:** RSA 2048-bit or ECDSA
- **OCSP Stapling:** Enabled
- **Perfect Forward Secrecy:** Enabled

#### 5.5.4 Email Server Integration

**Self-Hosted Email Server:**

The production deployment includes a self-hosted email server on the same infrastructure for authentication and notification emails. Configuration:

```python
EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'
EMAIL_HOST = 'mail.janmack.de'
EMAIL_PORT = 587
EMAIL_USE_TLS = True
EMAIL_HOST_USER = 'noreply@janmack.de'
DEFAULT_FROM_EMAIL = 'Password Manager <noreply@janmack.de>'
```

**Benefits:**
- Consistent domain reputation (janmack.de)
- Full control over email delivery
- No third-party service dependencies
- Integration with monitoring stack

**Alternative:** The application supports any SMTP provider (Gmail, SendGrid, AWS SES, etc.) by updating environment variables.

#### 5.5.5 Deployment Access

**Public URLs:**
- **Application:** https://password.janmack.de
- **Monitoring:** https://grafana.janmack.de (restricted access)
- **Repository:** https://github.com/MackJan/PasswordManager
- **SonarCloud:** https://sonarcloud.io/dashboard?id=MackJan_PasswordManager

**Security Hardening:**
- SSH key-based authentication only (password login disabled)
- Fail2ban monitoring for brute-force attempts
- Regular security updates via unattended-upgrades
- Docker socket secured with proper permissions
- Environment variables managed via GitHub Secrets
- Database backups encrypted and stored off-site

---

## 6. Security Compliance Matrix

| Requirement                   | Implementation                                          |
|-------------------------------|---------------------------------------------------------|
| **Secure Credential Storage** | AES-256-GCM, 3-tier key hierarchy, HKDF salt derivation |
| **Server-Side Encryption**    | All encryption in Django backend                        |
| **TLS Protection**            | HTTPS enforced, HSTS headers                            |
| **Master Password Security**  | Argon2 hashing, never stored plaintext                  |
| **Session Security**          | Secure cookies, HttpOnly, SameSite=Strict               |
| **Optional MFA**              | TOTP + recovery codes via django-allauth                |
| **SQL Injection Prevention**  | Django ORM parameterized queries                        |
| **XSS Prevention**            | Template auto-escaping, CSP headers                     |
| **CSRF Protection**           | Django middleware, tokens on all forms                  |
| **Access Control**            | Per-user ownership, login required                      |
| **Generic Error Messages**    | No stack traces or internals exposed                    |
| **Comprehensive Logging**     | Structured JSON logs, Grafana monitoring                |

---

## 7. Known Limitations & Future Improvements

### 7.1 Current Limitations

1. **No Client-Side Encryption:** Encryption happens server-side (acceptable for this architecture)
2. **Single AMK:** No automatic AMK rotation workflow (manual process)
3. **No Password Sharing:** Individual vault items cannot be shared between users
4. **No Password History:** Previous password versions not tracked
5. **No Breach Detection:** No integration with HaveIBeenPwned API

### 7.2 Potential Enhancements

1. **Password Generator:** Built-in strong password generation
2. **Browser Extension:** Auto-fill credentials in web forms
3. **Import/Export:** Support for importing from other password managers
4. **Audit Log:** Detailed access log for each vault item
5. **Biometric Authentication:** WebAuthn/FIDO2 support
6. **Zero-Knowledge Architecture:** Client-side encryption option
7. **Password Strength Meter:** Real-time feedback during entry creation

---

### 7.3 Accepted SonarQube issues
Currently Open:

37 Code smell issues

8 Accepted "Cross-Site Request Forgery (CSRF)" Security Hotspots
- These are accepted due to the use of Django's built-in CSRF protection which adequately mitigates CSRF risks.
- Those hotspots are in my opinion also false positives since they are always raised when allowing POST requests for a view.

3 Accepted Security Hotspots for the local and production deployment Dockerfile

They can all be viewed in the [SonarCloud dashboard](https://sonarcloud.io/summary/new_code?id=MackJan_PasswordManager&branch=main)

## 8. Conclusion

This password manager successfully implements all required security features for the ICS0020 course project:

✅ **Secure Storage:** AES-256-GCM with hierarchical key management  
✅ **Strong Authentication:** Argon2 + optional TOTP 2FA  
✅ **SQL Injection Prevention:** Django ORM parameterized queries  
✅ **XSS Prevention:** Template auto-escaping + CSP  
✅ **CSRF Protection:** Django middleware + tokens  
✅ **Access Control:** Per-user ownership enforcement  
✅ **Error Handling:** Generic messages + comprehensive logging  

The application demonstrates production-ready security practices including:
- Defense in depth (multiple security layers)
- Principle of least privilege (minimal access rights)
- Secure by default (all security features enabled)
- Comprehensive monitoring and logging
- Containerized deployment for consistency

**Production Deployment:** [https://password.janmack.de](https://password.janmack.de)

---

## 9. References

- **Django Documentation:** https://docs.djangoproject.com/
- **OWASP Top 10:** https://owasp.org/www-project-top-ten/
- **django-allauth:** https://docs.allauth.org/
- **Cryptography Library:** https://cryptography.io/
- **NIST SP 800-63B:** Digital Identity Guidelines (Authentication)
- **NIST SP 800-132:** Recommendation for Password-Based Key Derivation

---

**Report Generated:** November 22, 2025  
**Author:** Project Analysis Tool  
**Course:** ICS0020 - Web Application Security
