# E-Office Authentication API Documentation

Welcome to the E-Office Authentication API for Krishna Kanta Handiqui State Open University (KKHSOU). This guide provides everything you need to integrate with our authentication services.

## Overview

The API provides secure authentication for two main user types:
1.  **Employees**: Internal staff of KKHSOU.
2.  **Exam Centers**: Authorized examination centers.

It supports both traditional email/password logins and Google OAuth2 for a seamless and secure user experience.

*   **Base URL**: All endpoints are prefixed with `https://eservices.kkhsou.ac.in/auth/api/`.
*   **Supported Methods**: The primary method for creating authentication sessions is `POST`. `GET` is used for initiating OAuth flows and exchanging tokens.
*   **Response Format**: All responses are in `JSON` format.

### Prerequisites

Before you begin, ensure you have the following:
*   Your application must be able to handle redirects and process URL query parameters.

---

## Authentication Flows

The API uses a two-step authentication process to enhance security. Whether logging in via email/password or Google, the flow is:
1.  The user authenticates with the backend.
2.  The backend validates the user and redirects back to your frontend application with a secure, single-use temporary `code`.
3.  Your frontend application exchanges this `code` for JWT (JSON Web Token) access and refresh tokens.

### 1. Manual (Email & Password) Login

This flow is for employees with registered accounts.

#### **Step 1: Authenticate User**

Make a `POST` request with the user's email and password.

*   **Endpoint**: `/api/m_login/`
*   **Method**: `POST`

**Query Parameters:**

| Parameter      | Type     | Description                                                                                                                              |
| :------------- | :------- | :--------------------------------------------------------------------------------------------------------------------------------------- |
| `response_uri` | `string` | **Required**. The URI of your frontend page that will handle the callback from our API. **Example:** `http://your-frontend-domain.com/login-response/` |

**Request Body:**

```json
{
    "email": "user@kkhsou.in",
    "password": "userpassword"
}
```

**Response:**

On successful authentication, the API responds with a `302 Found` redirect to the provided `response_uri` (or the referring page). The redirect URL will contain a temporary `code` and status.

*   **Success Redirect URL:** `<response_uri>?code=<temporary_uuid_code>&status=200`
*   **Failure Redirect URL:** `<response_uri>?error=Invalid+credentials&status=401`

#### **Step 2: Exchange Temporary Code for Tokens**

Once your frontend receives the temporary `code`, proceed to the **Exchanging the Code for Tokens** section to get the JWT tokens.

*   **Endpoint**: `/api/token-exchange/`
*   **Method**: `GET`

This code is valid for **5 minutes**.

**Query Parameters:**

| Parameter | Type   | Description                               |
| :-------- | :----- | :---------------------------------------- |
| `code`    | `UUID` | **Required**. The temporary code from Step 1. |


**cURL Example:**

```bash
curl -X GET "https://eservices.kkhsou.ac.in/auth/api/token-exchange/?code=a1b2c3d4-e5f6-7890-1234-567890abcdef"
```

**Python `requests` Example:**

```python
import requests

temp_code = "a1b2c3d4-e5f6-7890-1234-567890abcdef"
url = f"https://eservices.kkhsou.ac.in/auth/api/token-exchange/?code={temp_code}"

response = requests.get(url)

if response.status_code == 200:
    data = response.json()
    print("Authentication successful:", data)
    # The response body contains tokens and user_type
else:
    print("Token exchange failed:", response.json())

```

**Success Response (`200 OK`):**

The API returns the `access` and `refresh` tokens, along with the access token's max age and the user type. **The frontend is responsible for storing and managing these tokens.**

```json
{
  "refresh": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "access": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "access_max_age": 900,
  "user_type": "employee"
}
```


---

### 2. Google OAuth2 Login (Employees & Exam Centers)

This flow allows users to authenticate using their Google account. The process is similar for both employees and exam centers, with a specific parameter to differentiate them.

#### **Step 1: Redirect to Google's Consent Screen**

Initiate the login by redirecting the user to the API, which in turn redirects them to Google.

*   **Endpoint**: `/api/google/`
*   **Method**: `GET`

**Query Parameters:**

| Parameter      | Type      | Description                                                                                             |
| :------------- | :-------- | :------------------------------------------------------------------------------------------------------ |
| `response_uri` | `string`  | **Required**. The URI of your frontend page that will handle the callback from our API.                 |
| `exam_center`  | `boolean` | **Optional**. Set to `true` to initiate the login flow for an Exam Center. Defaults to `false`.         |

**Example:**

Create a login link in your frontend application pointing to this endpoint. To log in as an exam center, add `&exam_center=true`. (Note: Change `response_uri` to your actual frontend URL.)

```html
<a href="https://eservices.kkhsou.ac.in/auth/api/google/
response_uri=http://localhost:3000/auth/callback&exam_center=true">
  Login with Google
</a>
```

The user is sent to the Google login page. After they consent, Google redirects them to our backend callback endpoint.

#### **Step 2: Handle the Callback and Exchange Code**

This step is handled automatically.
1.  Google redirects the user to `/api/google/callback/`.
2.  Our backend verifies the user with Google, checks if they are an approved user in our system, and then redirects back to the `response_uri` you provided in Step 1.
3.  This final redirect contains the temporary `code` needed to get the JWT tokens.

Your frontend application at `response_uri` will receive the code just like in the manual login flow.

*   **Employee Success URL:** `<response_uri>?code=<temporary_uuid_code>&status=200`

*   **Exam Center Success URL:** `<response_uri>?code=<temporary_uuid_code>&exam_center=true&status=200`

*   **Failure Redirect URL:** `<response_uri>?error=User+not+found&status=404`

#### **Step 3: Exchange Temporary Code for Tokens**

Use the `code` from the redirect URL to call the `/api/token-exchange/` endpoint. **If you received `exam_center=true` in the redirect, be sure to include it in your request to the token exchange endpoint.**

---

## Token Management

### Refreshing the Access Token

The `access_token` has a short lifetime (15 minutes). Once it expires, you must use the `refresh_token` to get a new one without forcing the user to log in again.

*   **Endpoint**: `/api/refresh-access/`
*   **Method**: `POST`
*   **Request Body**:
    *   **For browser-based clients**: The body can be empty, as the `refresh_token` is sent automatically via an `HttpOnly` cookie.
    *   **For server-to-server clients**: The refresh token must be included in the request body.
    ```json
    {
        "refresh": "your_refresh_token_here"
    }
    ```

**Success Response (`200 OK`):**

The API returns a new `access_token` in the JSON response. The frontend is responsible for updating its stored access token.

```json
{
    "access": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

**Error Response (`400 BAD-REQUEST`):**

If the refresh token is invalid, expired, or missing, the request will fail with a `400 BAD-REQUEST` status. The user must log in again.

### Verifying JWT with Public Key

For services that need to verify the JWT signature independently, the public key is available.

*   **Endpoint**: `/api/public-key/`
*   **Method**: `GET`

**Success Response (`200 OK`):**

```json
{
    "public_key": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----"
}
```

---

## Account Management

### Change Password

This endpoint manages a two-step password change process using an email-based OTP (For employees only).

*   **Endpoint**: `/api/change-password/`
*   **Method**: `POST`

#### **Step 1: Request OTP**

Provide the user's email to receive an OTP.

**Request Body:**
```json
{
    "email": "user@kkhsou.in"
}
```

**Response (`200 OK`):**
```json
{ "message": "OTP sent successfully" }
```

#### **Step 2: Verify OTP and Set New Password**

Provide the email, the OTP received, and the new password.

**Request Body:**
```json
{
    "email": "user@kkhsou.in",
    "otp": "123456",
    "new_password": "newSecurePassword123"
}
```

**Response (`200 OK`):**
```json
{ "message": "Password changed successfully" }
```

---

## Common Response Formats

#### Success Response (Token Exchange)

A successful token exchange returns tokens and user metadata in the response body for the client to manage.

```json
{
  "refresh": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "access": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "access_max_age": 900,
  "user_type": "employee"
}
```

#### Error Response

Errors from endpoints like `/api/token-exchange/` or `/api/change-password/` follow a standard format. Redirect-based flows will pass the error message as a URL query parameter.

```json
{
    "error": "Error message",
    "details": "Optional detailed message"
}
```

---

## Error Handling

The API uses standard HTTP status codes to indicate the success or failure of a request.

| Status Code | Meaning             | Reason & Fix                                                                                             |
| :---------- | :------------------ | :------------------------------------------------------------------------------------------------------- |
| `400`       | Bad Request         | A required parameter is missing or invalid (e.g., no `code` for token exchange), or an invalid/expired `refresh_token` was used. Check your request payload and parameters. |
| `403`       | Forbidden           | The user's account exists but has not been approved by an administrator. Contact support for account approval. |
| `404`       | Not Found           | The requested resource could not be found. This includes invalid API endpoints, non-existent user emails, or incorrect passwords for manual login. |
| `500`       | Internal Server Error | An unexpected error occurred on the server. If this persists, please report the issue.                 |

---

## Security Notes

*   **HTTPS**: Always use `HTTPS` for all API requests to protect sensitive data in transit.
*   **Token Storage**: Since tokens are returned in the response body, it is the frontend's responsibility to store them securely. Avoid storing tokens in `localStorage` to prevent XSS attacks.
*   **Token Lifetime**:
    *   `access_token`: **15 minutes**. Use this token to access protected resources.
    *   `refresh_token`: **8 hours**. Use this token to get a new `access_token`.
*   **CSRF Protection**: Django's built-in CSRF protection is active on all state-changing `POST` requests. Ensure your frontend sends the `csrftoken` cookie value in the `X-CSRFToken` header.
*   **Asymmetric Signing**: JWTs are signed with the `RS256` algorithm, ensuring that tokens can be verified with a public key without exposing the private signing key.

---


This document provides a complete guide to integrating with the E-Office Authentication API. For further questions, please contact the development team.