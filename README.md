# API Documentation

## Authentication Endpoints

### 1. Google OAuth2 Login

**URL:** `/api/google/`  
**Method:** `GET`  
**Description:**  
Redirects the user to the Google OAuth2 consent screen.

**Query Parameters:**
- `response_uri` (required): The frontend URI to redirect to after authentication.


**Usage Example:**
```
GET /api/google/?response_uri=http://localhost:3000/auth/callback
```

**Response:**  
Redirects to Google OAuth2 login page.

---

### 2. Google OAuth2 Callback

**URL:** `/api/google/callback/`  
**Method:** `GET`  
**Description:**  
Handles the callback from Google after user authentication. Only allows login for existing and approved users.

**Query Parameters:**
- `code`: The authorization code returned by Google.
- `state`: The encoded frontend redirect URI.

**Usage Example:**  
This endpoint is called by Google after user login. No direct usage.

> [!CAUTION]
>
> The `/api/google/callback/` endpoint is **not intended for direct user access**.
> It is used internally by the Google OAuth2 flow and should only be called by Google after user authentication.
>
> Users and frontend applications should never call this endpoint directly.


**Response:**  
- On success: Redirects to the frontend with a temporary `code` and `status=200`. `code` is valid for 5 minutes.
- On failure: Redirects to the frontend with an error message and appropriate status.

---

### 3. Token Exchange

**URL:** `/api/token-exchange/`  
**Method:** `GET`  
**Description:**  
Exchanges the temporary code (from Google callback) for JWT tokens and user info.

**Query Parameters:**
- `code` (required): The temporary code received from the Google callback redirect.

**Usage Example:**
```
GET /api/token-exchange/?code=<uuid_code>
```

**Response:**
- `200 OK`  
  ```json
  {
    "emp_id": 2,
    "official_email": "user@kkhsou.in",
    "name": "User Name",
    "profile_pic": "/media/profile_pics/...",
    "designation": ...,
    "dept": ...,
    "emp_category": "...",
    "user_type": "...",
  }
  ```
- `400 Bad Request`  
  ```json
  { "error": "Missing code" }
  ```
  or  
  ```json
  { "error": "Invalid or expired code" }
  ```

---

### 4. Manual Login

**URL:** `/api/login/`  
**Method:** `POST`  
**Description:**  
Authenticates user with email and password, returns JWT tokens.

**Request Body:**
```json
{
    "email": "user@kkhsou.in",
    "password": "userpassword"
}
```

**Response:**
- `200 OK`: Redirects to frontend with temporary code
- `401 Unauthorized`: Invalid credentials
- `403 Forbidden`: Account not approved
- `404 Not Found`: Email not found

---

### 5. Change Password

**URL:** `/api/change-password/`  
**Method:** `POST`  
**Description:**  
Two-step password change process using email OTP verification.

**Step 1 - Request OTP:**
```json
{
    "email": "user@kkhsou.in"
}
```

**Response:**
- `200 OK`: OTP sent successfully
- `404 Not Found`: Email not found
- `500 Internal Server Error`: Email sending failed

**Step 2 - Verify OTP and Change Password:**
```json
{
    "email": "user@kkhsou.in",
    "otp": "123456",
    "new_password": "newpassword123"
}
```

**Response:**
- `200 OK`: Password changed successfully
- `400 Bad Request`: Invalid OTP
- `404 Not Found`: Email not found

---

### 6. Public Key Endpoint

**URL:** `/api/public-key/`  
**Method:** `GET`  
**Description:**  
Returns the public key for JWT token verification.

**Response:**
- `200 OK`:
```json
{
    "public_key": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----"
}
```

## Security Features

### JWT Token Configuration
- Algorithm: RS256 (asymmetric signing)
- Access Token Lifetime: 15 minutes
- Refresh Token Lifetime: 1 day
- Token contains: emp_id, email, department, designation

### Password Security
- Passwords are hashed using Django's password hasher
- OTP verification for password reset
- Email notifications for password changes

## Notes

- All endpoints under `/api/` are public for authentication purposes
- JWT tokens use RS256 algorithm with asymmetric key pairs
- OTPs for password reset expire after 5 minutes
- Emails are sent from noreply@kkhsou.in
- The `/api/google/callback` endpoint is **not intended for direct user access**

## Error Responses

All error responses follow the format:
```json
{
    "error": "Error message",
    "details": "Optional detailed message"
}
```

Common status codes:
- `400`: Bad Request
- `401`: Unauthorized
- `403`: Forbidden
- `404`: Not Found
- `500`: Internal Server Error

---


<!-- For more details, see the implementation in -->
