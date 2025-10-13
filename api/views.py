from django.core.cache import cache
from django.shortcuts import redirect, get_object_or_404
from django.conf import settings
from django.core.mail import send_mail
from django.utils.html import strip_tags

from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework import status
from rest_framework_simplejwt.tokens import RefreshToken, UntypedToken
from rest_framework.permissions import AllowAny
from urllib.parse import urlencode, parse_qs
import requests, base64, uuid, logging

from .models import *
from .serializers import *
# Create your views here.

logger = logging.getLogger(__name__)


def authenticate_and_redirect(email, redirect_uri, password=None, m_login = False):
    """ Authenticate user and redirect to frontend with tokens in query params.
    Args:
        email (str, required): User's email for authentication.
        redirect_uri (str, required): URI to redirect after authentication.
        password (str | None, Optional): User's password for manual login. Defaults to None.
        m_login (bool, Optional): Flag for manual login flow. Defaults to False.

    Returns:
        HttpResponseRedirect: Redirect response with tokens or error message.
    """
    user = Employee.objects.filter(official_email=email).first()
    invalidUser = False

    if not user:
        invalidUser = True
    
    if m_login and user and not user.check_password(password):
        invalidUser = True
    
    if invalidUser:
        # allow only existing users to login
        logger.warning(f"Login attempt with invalid credentials: {email}")
        return redirect(f"{redirect_uri}?error=Invalid credentials.&status=404")
    
    if not user.approved:
        logger.warning(f"Login attempt with unapproved user: {email}")
        return redirect(f"{redirect_uri}?error=Approval pending, try again later&status=403") # only approved users can login
        
    refresh = RefreshToken.for_user(user)

    # Add custom claims to the token payload
    refresh['official_email'] = user.official_email
    refresh['dept_name'] = user.dept.name if user.dept else None

    respData = urlencode({
        "refresh": str(refresh),
        "access": str(refresh.access_token),
        "e_id": user.emp_id,            
    })
    logger.info(f"User {email} logged in successfully.")

    uuidCode = str(uuid.uuid4())
    cache.set(uuidCode, respData, timeout=300)
    return redirect(f"{redirect_uri}?code={uuidCode}&status=200")





class Google_login(APIView):
    permission_classes = [AllowAny]
    def get(self, request):
        frontend_redirect_uri = request.GET.get("response_uri", request.META.get('HTTP_REFERER'))

        state = base64.urlsafe_b64encode(frontend_redirect_uri.encode()).decode()
        
        scopes = [
            'https://www.googleapis.com/auth/userinfo.email',
            'https://www.googleapis.com/auth/userinfo.profile',
        ]
        query_params = urlencode({
            'client_id': settings.GOOGLE_CLIENT_ID,
            'redirect_uri': settings.GOOGLE_REDIRECT_URI,
            'response_type': 'code',
            'scope': ' '.join(scopes),
            'state': state,
            'prompt': 'consent', # optional: to get refresh token
        })
        auth_url = f'https://accounts.google.com/o/oauth2/v2/auth?{query_params}'
        return redirect(auth_url)
    

class Google_callback(APIView):
    ''' Handle Google OAuth2 callback '''

    def get(self, request):
        code = request.GET.get("code")
        state = request.GET.get("state")
        frontend_redirect_uri = base64.urlsafe_b64decode(state).decode()

        try:        
            token_resp = requests.post(
                "https://oauth2.googleapis.com/token",
                data={
                    "code": code,
                    "client_id": settings.GOOGLE_CLIENT_ID,
                    "client_secret": settings.GOOGLE_CLIENT_SECRET,
                    "redirect_uri": settings.GOOGLE_REDIRECT_URI,
                    "grant_type": "authorization_code",
                },
            ).json()

            access_token = token_resp.get("access_token")

            user_info = requests.get(
                "https://www.googleapis.com/oauth2/v2/userinfo",
                headers={"Authorization": f"Bearer {access_token}"},
            ).json()

        except Exception as e:
            logger.error(f"OAuth2 Error: {str(e)}")
            return redirect(f"{frontend_redirect_uri}?error=OAuth2 Error, try again later.&status=500")
        
        email = user_info.get("email")
        name = user_info.get("name", "")
        picture = user_info.get("picture", "")

        return authenticate_and_redirect(email, redirect_uri=frontend_redirect_uri, m_login=False)


class Manual_login(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        email = request.data.get("email")
        password = request.data.get("password")
        
        if not email or not password:
            return Response({"error": "Missing email or password"}, status=status.HTTP_400_BAD_REQUEST)
        
        frontend_redirect_uri = request.GET.get("response_uri", request.META.get('HTTP_REFERER'))
        return authenticate_and_redirect(email, frontend_redirect_uri, password, m_login=True)
    

class ChangePasswordView(APIView):
    def post(self, request):
        try:
            email = request.data.get("email")
            otp = request.data.get("otp")
            user = Employee.objects.filter(official_email=email).first()
            print(otp)
            if not user:
                return Response({"error": "Email not found"}, status=status.HTTP_404_NOT_FOUND)

            if not otp or otp == '':
                new_otp = str(uuid.uuid4())[:6]

                html_message = f'''
                    <h2>Password Reset Request</h2>
                    <p>Your OTP for password reset in KKHSOU E-Office is: <strong>{new_otp}</strong></p>
                    <p>This OTP will expire soon. Please do not share this with anyone.</p>
                '''
                
                # Plain text version
                plain_message = strip_tags(html_message)

                try:
                    send_mail(
                        subject='Password Reset OTP',
                        message=plain_message,
                        from_email=settings.EMAIL_HOST_USER,
                        recipient_list=[email],
                        html_message=html_message,
                        fail_silently=False,
                    )
                
                    return Response({
                        'message': 'OTP sent successfully',
                        'otp': new_otp
                    }, status=status.HTTP_200_OK) 

                except Exception as e:
                    logger.error(f"Failed to send email: {e}")
                    return Response({
                        'error': 'Failed to send email',
                        'details': str(e)
                    }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            
            new_password = request.data.get("new_password")

            if not new_password:
                return Response({"error": "Missing new password"}, status=status.HTTP_400_BAD_REQUEST)

            user.set_password(new_password)
            user.save()

            return Response({"message": "Password changed successfully"}, status=status.HTTP_200_OK)
        
        except Exception as e:
            logger.error(f"Password change failed: {e}")
            return Response({"error": "Password change failed"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)





class TokenExchange(APIView):
    ''' Exchange code for tokens and user info '''
    permission_classes = [AllowAny]

    def get(self, request):
        code = request.GET.get("code")
        if not code:
            return Response({"error": "Missing code"}, status=status.HTTP_400_BAD_REQUEST)
        
        data = cache.get(code)
        if not data:
            return Response({"error": "Invalid or expired code"}, status=status.HTTP_400_BAD_REQUEST)
        
        parsed = parse_qs(data)
        e_id = parsed.get("e_id")[0]

        user = get_object_or_404(Employee, emp_id=e_id)
        empSerializer = EmployeeSerializer(user)

        cache.delete(code)
        respData = {
            'user': empSerializer.data,
            'refresh': parsed.get("refresh")[0],
            'access': parsed.get("access")[0]
        }
        return Response(respData, status=status.HTTP_200_OK)


class RefreshAccessToken(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        try:
            print('refresh access request received')
            refresh_token = request.data["refresh"]
            token = RefreshToken(refresh_token)
            
            # Verify the refresh token
            UntypedToken(refresh_token)

            # Generate a new access token
            access_token = str(token.access_token)
            
            return Response({"access": access_token}, status=status.HTTP_200_OK)
        except Exception as e:
            logger.error(f"Token renewal failed: {e}")
            return Response({"error": "Invalid refresh token or server error."}, status=status.HTTP_400_BAD_REQUEST)


class PublicKeyView(APIView):
    """
    Exposes the public key for other services to verify JWTs.
    This is used when you configure SimpleJWT to use asymmetric signing (e.g., RS256).
    """
    permission_classes = [AllowAny]

    def get(self, request, *args, **kwargs):
        # Simple JWT's settings object automatically derives the public key
        # from the private SIGNING_KEY if VERIFYING_KEY is not set explicitly
        # for this purpose. We will read it from settings.
        try:
            public_key = settings.SIMPLE_JWT['VERIFYING_KEY']
            return Response({'public_key': public_key})
        except Exception as e:
            logger.error(f"Could not retrieve public key: {e}")
            return Response({"error": "Could not retrieve public key."}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


# class LogoutView(APIView):
#     """
#     Blacklists a refresh token to log a user out.
#     """
#     permission_classes = [AllowAny]

#     def post(self, request):
#         try:
#             refresh_token = request.data["refresh"]
#             token = RefreshToken(refresh_token)
#             token.blacklist()
#             logger.info(f"User logged out successfully by blacklisting token.")
#             return Response(status=status.HTTP_205_RESET_CONTENT)
#         except Exception as e:
#             logger.error(f"Logout failed: {e}")
#             return Response({"error": "Invalid token or server error."}, status=status.HTTP_400_BAD_REQUEST)
