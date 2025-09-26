from django.core.files.base import ContentFile
from django.core.cache import cache
from django.shortcuts import redirect, get_object_or_404
from django.conf import settings

from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework import status
from rest_framework_simplejwt.tokens import RefreshToken, UntypedToken
from rest_framework.permissions import IsAuthenticated, AllowAny
from urllib.parse import urlencode, parse_qs
from django.http import JsonResponse
from django.contrib.auth import login, logout
import requests, base64, uuid, logging

from .models import *
from .serializers import *
# Create your views here.

logger = logging.getLogger(__name__)

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

        # Find the user by their official email, which is the unique identifier
        user = Employee.objects.filter(official_email=email).first() # Use official_email as it's the USERNAME_FIELD
        if not user:
            # allow only existing users to login
            logger.warning(f"Login attempt with unregistered email: {email}")
            return redirect(f"{frontend_redirect_uri}?error=Email not registered.&status=404")
        
        
        if not user.approved:
            logger.warning(f"Login attempt with unapproved user: {email}")
            return redirect(f"{frontend_redirect_uri}?error=Approval pending, try again later&status=403") # only approved users can login
        
        # if not user.profile_pic:
        #     response = requests.get(picture)
        #     if response.status_code == 200:
        #         file_name = f'{uuid.uuid4()}_{user.emp_id}.jpg'
        #         user.profile_pic.save(file_name, ContentFile(response.content), save=True)
        #         user.save()
                

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
        return redirect(f"{frontend_redirect_uri}?code={uuidCode}&status=200")


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
