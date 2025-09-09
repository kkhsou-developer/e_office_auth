from django.core.files.base import ContentFile
from django.core.cache import cache
from django.shortcuts import redirect, get_object_or_404
from django.conf import settings

from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework import status
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.permissions import IsAuthenticated, AllowAny
from urllib.parse import urlencode, parse_qs
from django.http import JsonResponse
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

        # if not code:
        #     return redirect
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
            return redirect(f"{frontend_redirect_uri}?error=oauth_failed! Try again later.&status=500")
        
        email = user_info.get("email")
        name = user_info.get("name", "")
        picture = user_info.get("picture", "")

        # user = Employee.objects.get_or_create(email=email)
        user = Employee.objects.filter(email=email).first()
        if not user:
            # allow only existing users to login
            logger.warning(f"Login attempt with unregistered email: {email}")
            return Response({"error": "User not found"}, status=status.HTTP_404_NOT_FOUND) 
        
        
        if not user.approved:
            logger.warning(f"Login attempt with unapproved user: {email}")
            return redirect(f"{frontend_redirect_uri}?error=approval_pending! Try again later.&status=403") # only approved users can login
        
        if not user.profile_pic:
            response = requests.get(picture)
            if response.status_code == 200:
                file_name = f'{uuid.uuid4()}_{user.emp_id}.jpg'
                user.profile_pic.save(file_name, ContentFile(response.content), save=True)
                user.save()
                

        refresh = RefreshToken.for_user(user)

        respData = urlencode({
            "refresh": str(refresh),
            "access": str(refresh.access_token),
            "e_id": user.emp_id,            
        })
        logger.info(f"User {email} logged in successfully.")

        uuidCode = str(uuid.uuid4())
        cache.set(uuidCode, respData, timeout=300)
        return redirect(f"{frontend_redirect_uri}?code={uuidCode}&status=200")



def write_to_file(data, filename="output.txt"):
    with open(filename, "a") as f:
        f.write(str(data))



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
        
        # cache.delete(code)
        return Response(empSerializer.data, status=status.HTTP_200_OK)
