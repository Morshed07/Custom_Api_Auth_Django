from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView
from django.core.mail import send_mail
from .models import User, OTP
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth import authenticate
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

            #send_email
            send_mail(
                'Verify ur email by this otp code',
                f'Your OTP code is {otp}',
                [user.email],
                fail_silently=False,
            )

            return Response({'message': 'OTP sent to your email'}, status=status.HTTP_201_CREATED)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    

class VerifyOTPView(APIView):
    def post(self, request):
        email = request.data.get('email')
        otp_code = request.data.get('otp')

        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            return Response({'error': 'Invalid email'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            otp = OTP.objects.filter(user=user).last()
        except OTP.DoesNotExist:
            return Response({'error': 'Invalid OTP'}, status=status.HTTP_400_BAD_REQUEST)

        if otp and otp.otp == otp_code and otp.is_valid():
            user.is_active = True
            user.save()

            return Response({'message': 'Your account has been activated'}, status=status.HTTP_200_OK)

        return Response({'error': 'Invalid or expired OTP'}, status=status.HTTP_400_BAD_REQUEST)
    

class LoginView(APIView):
    def post(self, request):
        email = request.data.get('email')
        password = request.data.get('password')

        user = authenticate(request, email=email, password=password)

        if user is not None:
            if user.is_active:
                refresh = RefreshToken.for_user(user)
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
