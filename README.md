# API Documentation

## Authentication Endpoints

### 1. Google OAuth2 Login

**URL:** `/api/auth/google/`  
**Method:** `GET`  
**Description:**  
Redirects the user to the Google OAuth2 consent screen.

**Query Parameters:**
- `response_uri` (required): The frontend URI to redirect to after authentication.


**Usage Example:**
```
GET /api/auth/google/?response_uri=http://localhost:3000/auth/callback
```

**Response:**  
Redirects to Google OAuth2 login page.

---

### 2. Google OAuth2 Callback

**URL:** `/api/auth/google/callback/`  
**Method:** `GET`  
**Description:**  
Handles the callback from Google after user authentication. Only allows login for existing and approved users.

**Query Parameters:**
- `code`: The authorization code returned by Google.
- `state`: The encoded frontend redirect URI.

**Usage Example:**  
This endpoint is called by Google after user login. No direct usage.

> [!CAUTION]
> **⚠️ Caution**
>
> The `/api/auth/google/callback/` endpoint is **not intended for direct user access**.
> It is used internally by the Google OAuth2 flow and should only be called by Google after user authentication.
>
> Users and frontend applications should never call this endpoint directly.


**Response:**  
- On success: Redirects to the frontend with a temporary `code` and `status=200`. `code` is valid for 5 minutes.
- On failure: Redirects to the frontend with an error message and appropriate status.

---

### 3. Token Exchange

**URL:** `/api/auth/token-exchange/`  
**Method:** `GET`  
**Description:**  
Exchanges the temporary code (from Google callback) for JWT tokens and user info.

**Query Parameters:**
- `code` (required): The temporary code received from the Google callback redirect.

**Usage Example:**
```
GET /api/auth/token-exchange/?code=<uuid_code>
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

## Notes

- All endpoints under `/api/auth/` are public for authentication purposes.
- The `/api/auth/google/callback` endpoint is **not intended for direct user access**.
- Only existing and approved users can log in via Google OAuth2.
- JWT tokens are returned via the token exchange endpoint, not directly from the callback.

---


<!-- For more details, see the implementation in -->