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

import json
# Create your views here.

logger = logging.getLogger(__name__)

def saveLoginLog(**kwargs):
    """
    Creates a LoginLog entry from keyword arguments.
    The keys in kwargs should match the fields of the LoginLog model.
    """
    LoginLog.objects.create(**kwargs)


def authenticate_employee(request, email, redirect_uri, password=None, m_login = False, ip=None, agent=None):
    """ Authenticate user and redirect to frontend with tokens in query params.
    Args:
        request (HttpRequest): The request object.
        email (str, required): User's email for authentication.
        redirect_uri (str, required): URI to redirect after authentication.
        password (str, optional): User's password for manual login. Defaults to None. 
        m_login (bool, Optional): Flag for manual login flow. Defaults to False.

    Returns:
        HttpResponseRedirect: Redirect response with tokens or error message.
    """
    user = Employee.objects.filter(official_email=email).first()

    loginLogData = {
        'user': user,
        'ip_address': ip or request.META.get('REMOTE_ADDR'),
        'user_agent': agent or request.META.get('HTTP_USER_AGENT'),
        'attempt_email': email,
        'auth_method': 'email_password' if m_login else 'google_oauth2',
    }

    if not user:
        saveLoginLog(login_successful=False, failure_reason="Account is not registered.", **loginLogData)
        logger.warning(f"Login attempt with invalid email: {email}")
        return redirect(f"{redirect_uri}?error=Account is not registered.&status=404")
    
    if m_login and user and not user.check_password(password):
        saveLoginLog(login_successful=False, failure_reason="Invalid credentials.", **loginLogData)
        logger.warning(f"Login attempt with invalid credentials: {email}")
        return redirect(f"{redirect_uri}?error=Invalid credentials.&status=404")
    
    
    if not user.approved:
        saveLoginLog(login_successful=False, failure_reason="Account not approved.", **loginLogData)
        logger.warning(f"Login attempt with unapproved user: {email}")
        return redirect(f"{redirect_uri}?error=Approval pending, try again later&status=403") # only approved users can login
        
    refresh = RefreshToken.for_user(user)

    saveLoginLog(login_successful=True, **loginLogData)

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



def authenticate_examCenter(request, email, redirect_uri, password=None, m_login = False):
    exam_center = ExamCenter.objects.filter(email=email).first()

    if not exam_center:
        logger.warning(f"Exam center login attempt with invalid email: {email}")
        return redirect(f"{redirect_uri}?error=Exam center email not found.&exam_center=true&status=404")

    if m_login and (not exam_center.password or not exam_center.check_password(password)):
            logger.warning(f"Exam Center login attempt with invalid credentials for {email}")
            return redirect(f"{redirect_uri}?error=Invalid credentials.&exam_center=true&status=404")
    
    refresh = RefreshToken.for_user(exam_center)
    refresh['user_type'] = 'exam_center'
    refresh['exam_center_code'] = exam_center.code
    refresh['email'] = exam_center.email

    logger.info(f"Exam center {email} ({exam_center.code}) logged in successfully.")

    respData = urlencode({
        "refresh": str(refresh),
        "access": str(refresh.access_token),
        "e_id": exam_center.id,
    })

    uuidCode = str(uuid.uuid4())
    cache.set(uuidCode, respData, timeout=300)
    return redirect(f"{redirect_uri}?code={uuidCode}&exam_center=true&status=200")


    



class Google_login(APIView):
    permission_classes = [AllowAny]
    def get(self, request):
        frontend_redirect_uri = request.GET.get("response_uri", request.META.get('HTTP_REFERER'))
        examCenter_login = str(request.GET.get("exam_center", 'false')).lower() == 'true'
        
        ip = request.META.get('REMOTE_ADDR')
        agent = request.META.get('HTTP_USER_AGENT')

        stateData = {
            'frontend_redirect_uri': frontend_redirect_uri,
            'ip': ip,
            'agent': agent,
            'examCenter_login': examCenter_login
        }

        state = base64.urlsafe_b64encode(json.dumps(stateData).encode()).decode()
        
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

        state_data = json.loads(base64.urlsafe_b64decode(state).decode())
        frontend_redirect_uri = state_data.get('frontend_redirect_uri')
        ip = state_data.get('ip')
        agent = state_data.get('agent')
        examCenter_login = state_data.get('examCenter_login')

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

        if examCenter_login:
            return authenticate_examCenter(request, email, redirect_uri=frontend_redirect_uri)
        
        return authenticate_employee(request, email, redirect_uri=frontend_redirect_uri, m_login=False, ip=ip, agent=agent)


class Manual_login(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        email = request.data.get("email")
        password = request.data.get("password")
        examCenter_login = str(request.GET.get("exam_center", 'false')).lower() == 'true'
        frontend_redirect_uri = request.GET.get("response_uri", request.META.get('HTTP_REFERER'))
        
        if not email or not password:
            return Response({"error": "Missing email or password"}, status=status.HTTP_400_BAD_REQUEST)
        
        if examCenter_login:
            return authenticate_examCenter(request, email, frontend_redirect_uri, password, m_login=True)
        
        return authenticate_employee(request, email, frontend_redirect_uri, password, m_login=True)    



class ChangePassword(APIView):
    def post(self, request):
        try:
            is_exam_center = str(request.data.get("exam_center", 'false')).lower() == 'true'
            email = request.data.get("email")
            otp = request.data.get("otp")
            
            user = None
            if is_exam_center:
                user = ExamCenter.objects.filter(email=email).first()
            else:
                user = Employee.objects.filter(official_email=email).first()

            if not user:
                if is_exam_center:
                    logger.warning(f"Password change attempt for non-existent exam center email: {email}")
                else:
                    logger.warning(f"Password change attempt for non-existent employee email: {email}")
                return Response({"error": "Email not found"}, status=status.HTTP_404_NOT_FOUND)

            if not otp or otp == '':
                new_otp = str(uuid.uuid4()).upper()[:6]
                # Store OTP in cache with a 5-minute timeout, keyed by email.
                cache.set(f"otp_{email}", new_otp, timeout=300)

                html_message = f"""
                <!DOCTYPE html>
                <html>
                <head>
                    <style>
                        .container {{
                            font-family: Arial, sans-serif;
                            line-height: 1.6;
                            color: #333;
                            max-width: 600px;
                            margin: 20px auto;
                            padding: 20px;
                            border: 1px solid #ddd;
                            border-radius: 5px;
                        }}
                        .header {{
                            background-color: #f2f2f2;
                            padding: 10px;
                            text-align: center;
                            border-bottom: 1px solid #ddd;
                        }}
                        .content {{ padding: 20px 0; }}
                        .otp-code {{
                            font-size: 24px;
                            font-weight: bold;
                            color: #0056b3;
                            text-align: center;
                            letter-spacing: 2px;
                            margin: 20px 0;
                            padding: 10px;
                            background-color: #e9ecef;
                            border-radius: 4px;
                        }}
                        .footer {{ font-size: 0.9em; text-align: center; color: #777; margin-top: 20px; }}
                    </style>
                </head>
                <body>
                    <div class="container">
                        <div class="header"><h2>Password Reset Request</h2></div>
                        <div class="content">
                            <p>Hello,</p>
                            <p>We received a request to reset the password for your account. Please use the following One-Time Password (OTP) to proceed:</p>
                            <div class="otp-code">{new_otp}</div>
                            <p>This OTP is valid for 5 minutes only. If you did not request a password reset, please ignore this email.</p>
                        </div>
                        <div class="footer">
                            <p>This is an automated message. Please do not reply to this email.</p>
                        </div>
                    </div>
                </body>
                </html>
                """
                
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
                
                    logger.info(f"Password reset OTP sent to {email}")
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

            cached_otp = cache.get(f"otp_{email}")

            if not cached_otp or cached_otp != otp:
                return Response({"error": "Invalid OTP"}, status=status.HTTP_400_BAD_REQUEST)

            cache.delete(f"otp_{email}") 
            user.set_password(new_password)
            user.save()

            logger.info(f"Password changed successfully for {email}")
            return Response({"message": "Password changed successfully"}, status=status.HTTP_200_OK)
        
        except Exception as e:
            logger.error(f"Password change failed: {e}")
            return Response({"error": "Password change failed"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)





class TokenExchange(APIView):
    ''' Exchange code for tokens and user info '''
    permission_classes = [AllowAny]

    def get(self, request):
        code = request.GET.get("code")
        is_examCenter = str(request.GET.get("exam_center", 'false')).lower() == 'true'

        if not code:
            return Response({"error": "Missing code"}, status=status.HTTP_400_BAD_REQUEST)
        
        data = cache.get(code)
        if not data:
            return Response({"error": "Invalid or expired code"}, status=status.HTTP_400_BAD_REQUEST)
        
        parsed = parse_qs(data)
        e_id = parsed.get("e_id")[0]

        respData = {
            'refresh': parsed.get("refresh")[0],
            'access': parsed.get("access")[0],
            'access_max_age' : int(settings.SIMPLE_JWT['ACCESS_TOKEN_LIFETIME'].total_seconds()),
        }

        if is_examCenter:
            exam_center = get_object_or_404(ExamCenter, id=e_id)
            respData['user_type'] = 'exam_center'
        else:
            user = get_object_or_404(Employee, emp_id=e_id)
            respData['user_type'] = 'employee'

        cache.delete(code)
        return Response(respData, status=status.HTTP_200_OK)


class RefreshAccessToken(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        try:
            refresh_token = request.data["refresh"]
            token = RefreshToken(refresh_token)
            
            # Verify the refresh token
            UntypedToken(refresh_token)

            # Generate a new access token
            access_token = str(token.access_token)
            
            return Response({"access": access_token, 'access_max_age': int(settings.SIMPLE_JWT['ACCESS_TOKEN_LIFETIME'].total_seconds())}, status=status.HTTP_200_OK)
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


