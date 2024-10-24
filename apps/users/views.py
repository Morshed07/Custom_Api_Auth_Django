from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView
from django.core.mail import send_mail
from .models import OTP
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth import authenticate
from channels.layers import get_channel_layer
from asgiref.sync import async_to_sync
from django.utils.timezone import now
from rest_framework.permissions import IsAuthenticated
import random
from .serializers import *

# Create your views here.

class RegisterView(APIView):
    def post(self, request):
        serializer = RegisterSerializer(data=request.data)
        
        if serializer.is_valid():
            user = serializer.save()
            user.is_active = False 
            user.save()

            #generate otp
            otp = random.randint(100000, 999999)
            OTP.objects.create(user=user, otp=otp)

            #send_mail
            send_mail(
                'Verify ur email by this otp code',
                f'Your OTP code is {otp}',
                'devxhub',
                [user.email],
                fail_silently=False,
            )

            return Response({'message': 'OTP sent to your email'}, status=status.HTTP_201_CREATED)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    

class VerifyOTPView(APIView):
    def post(self, request):
        otp_code = request.data.get('otp')
        
        if not otp_code:
            return Response({'error': 'OTP is required'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            otp = OTP.objects.get(otp=otp_code)
        except OTP.DoesNotExist:
            return Response({'error': 'Invalid OTP'}, status=status.HTTP_400_BAD_REQUEST)

        if not otp.is_valid():
            return Response({'error': 'OTP has expired'}, status=status.HTTP_400_BAD_REQUEST)

        user = otp.user
        if user.is_active:
            return Response({'message': 'Account is already active'}, status=status.HTTP_200_OK)

        user.is_active = True
        user.save()

        return Response({'message': 'Your account has been activated successfully'}, status=status.HTTP_200_OK)
    

class LoginView(APIView):
    def post(self, request):
        email = request.data.get('email')
        password = request.data.get('password')

        user = authenticate(request, email=email, password=password)

        if user is not None:
            if user.is_active:
                # Generate refresh and access tokens
                refresh = RefreshToken.for_user(user)

                # Check if the user is logging in for the first time
                if user.is_first_login:
                    user.is_first_login = False  # Mark as logged in
                    user.save()

                    # Send notification using Django Channels
                    channel_layer = get_channel_layer()
                    async_to_sync(channel_layer.group_send)(
                        "notifications", {  # Send notification to the 'notifications' group
                            'type': 'send_notification',
                            'message': f"User {user.email} has logged in for the first time!"
                        }
                    )

                # Return tokens on successful login
                return Response({
                    'refresh': str(refresh),
                    'access': str(refresh.access_token),
                }, status=status.HTTP_200_OK)
            else:
                return Response({'error': 'Account is not active, please verify OTP.'}, status=status.HTTP_403_FORBIDDEN)
        else:
            return Response({'error': 'Invalid email or password'}, status=status.HTTP_400_BAD_REQUEST)
        

class PasswordResetRequestView(APIView):
    def post(self, request):
        serializer = PasswordResetSerializer(data=request.data, context={'request': request})
        if serializer.is_valid():
            serializer.save()
            return Response({'message': 'Password reset link has been sent to your email'}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    

class PasswordResetConfirmView(APIView):
    def post(self, request, uidb64, token):
        request.data['uidb64'] = uidb64
        request.data['token'] = token
        
        serializer = PasswordResetConfirmSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({'message': 'Password has been reset successfully'}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    

class ChangePasswordView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, *args, **kwargs):
        serializer = ChangePasswordSerializer(data=request.data, context={'request': request})

        if serializer.is_valid():
            serializer.save()
            return Response({"message": "Password changed successfully"}, status=status.HTTP_200_OK)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)