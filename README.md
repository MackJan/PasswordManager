# Password Manager

This is a secure password manager web application built with Django. It is designed to store and manage your passwords securely, with a strong focus on encryption and security best practices. This project was developed as part of a web application security course.

Currently hosted on [Here](https://janmack.de)
## Features

*   **Secure Password Storage:** Store your passwords and other sensitive information in an encrypted vault.
*   **End-to-End Encryption:** Your data is encrypted at all stages, ensuring that only you can access it.
*   **Two-Factor Authentication (2FA):** Secure your account with TOTP (Time-based One-Time Password) based 2FA.
*   **Strong Encryption Standards:** Utilizes AES-256-GCM for data encryption, a widely trusted and secure encryption algorithm.
*   **Hierarchical Key Management:** Implements a robust key management system with an Application Master Key (AMK), User Master Keys (UMK), and Data Encryption Keys (DEK).
*   **Monitoring and Logging:** Integrated with Grafana and Loki for real-time monitoring and centralized logging of application events.
*   **Password Strength Checker:** Provides feedback on the strength of your passwords.
*   **Secure User Authentication:** Uses Argon2 for password hashing and secure login mechanisms.

## Technologies Used

*   **Backend:** Django, Django REST Framework
*   **Database:** PostgreSQL
*   **Encryption:** `cryptography` library (AES-256-GCM)
*   **Password Hashing:** Argon2 (`argon2-cffi`)
*   **Authentication:** `django-allauth` for authentication and MFA
*   **Containerization:** Docker, Docker Compose
*   **Monitoring:** Grafana, Loki, Promtail
*   **CI/CD:** SonarCloud for static code analysis

## Security

The security of this password manager is built on a multi-layered encryption strategy.

### Encryption Hierarchy

The encryption model is based on a hierarchical key structure:

1.  **Application Master Key (AMK):** A single, master key for the entire application. It is used to wrap the User Master Keys. The AMK is loaded from an environment variable or a file with restricted permissions.
2.  **User Master Key (UMK):** Each user has their own UMK, which is generated upon registration. The UMK is wrapped (encrypted) by the AMK and stored in the database. The UMK is never stored in its raw form.
3.  **Data Encryption Key (DEK):** Each item in the user's vault is encrypted with its own DEK. The DEK is then wrapped by the user's UMK.

This hierarchy ensures that even if the database is compromised, the user's data remains secure as the attacker would need access to the AMK and the user's credentials to decrypt the data.

### Encryption Algorithm

All encryption is performed using **AES-256-GCM**, which is an Authenticated Encryption with Associated Data (AEAD) mode. This not only provides confidentiality but also ensures the integrity and authenticity of the encrypted data.

### Two-Factor Authentication

Two-factor authentication is implemented using `django-allauth` and supports TOTP authenticators like Google Authenticator or Authy.

## Setup and Installation

This project is designed to be run with Docker and Docker Compose.

### Prerequisites

*   Docker
*   Docker Compose

### Running the Application

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/MackJan/PasswordManager.git
    cd PasswordManager
    ```

2.  **Create an environment file for development:**
    Create a `.env.dev` file in the `password_manager` directory with the following content:
    ```
    DEBUG=1
    SECRET_KEY='a-strong-and-random-secret-key'
    DJANGO_ALLOWED_HOSTS=localhost 127.0.0.1 [::1]
    SQL_ENGINE=django.db.backends.postgresql
    SQL_DATABASE=django_dev
    SQL_USER=django
    SQL_PASSWORD=django
    SQL_HOST=db
    SQL_PORT=5432
    ```

3.  **Build and run the containers:**
    ```bash
    docker-compose up --build
    ```

4.  **Access the application:**
    *   **Password Manager:** [http://localhost:8000](http://localhost:8000)
    *   **Grafana:** [http://localhost:3000](http://localhost:3000) (user: `admin`, password: `test_password!`)

## Monitoring

The application is configured with a monitoring stack consisting of Grafana, Loki, and Promtail.

*   **Loki:** Aggregates logs from the Django application and other services.
*   **Promtail:** An agent that ships logs from the local file system to Loki.
*   **Grafana:** A visualization tool to create dashboards for monitoring logs from Loki. A pre-configured dashboard is available to view application logs.

