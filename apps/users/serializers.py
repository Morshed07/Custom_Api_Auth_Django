from rest_framework import serializers
from django.core.mail import send_mail
from django.utils.encoding import force_bytes, force_str
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.template.loader import render_to_string
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.html import strip_tags
from django.conf import settings
from django.contrib.auth.password_validation import validate_password

from .models import User

class RegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, required=True)
    re_password = serializers.CharField(write_only=True, required=True)

    class Meta:
        model = User
        fields = ['email', 'password', 're_password']

    def validate(self, data):
        password = data.get('password')
        re_password = data.get('re_password')

        if password != re_password:
            raise serializers.ValidationError("password does not match !")
        return data

    def create(self, validated_data):
        validated_data.pop('re_password')
        user = User.objects.create_user(**validated_data)
        return user
    

class PasswordResetSerializer(serializers.Serializer):
    email = serializers.EmailField()

    def validate_email(self, value):
        try:
            user = User.objects.get(email=value)
        except User.DoesNotExist:
            raise serializers.ValidationError("User with this email does not exist.")
        return value

    def save(self):
        request = self.context.get('request')
        email = self.validated_data['email']
        user = User.objects.get(email=email)
        token_generator = PasswordResetTokenGenerator()

        uid = urlsafe_base64_encode(force_bytes(user.pk))
        token = token_generator.make_token(user)

        reset_link = f"http://{request.get_host()}/api/password-reset-confirm/{uid}/{token}/"

        subject = 'Password Reset Request'
        html_message = render_to_string('password_reset_email.html', {
            'user': user,
            'reset_link': reset_link,
        })
        message = strip_tags(html_message)
        send_mail(subject, message, settings.DEFAULT_FROM_EMAIL, [user.email])


class PasswordResetConfirmSerializer(serializers.Serializer):
    new_password = serializers.CharField(write_only=True, min_length=8)
    re_password = serializers.CharField(write_only=True, min_length=8)
    uidb64 = serializers.CharField()
    token = serializers.CharField()

    def validate(self, data):
        if data['new_password'] != data['re_password']:
            raise serializers.ValidationError("Passwords do not match.")
        
        try:
            uid = force_str(urlsafe_base64_decode(data['uidb64']))
            self.user = User.objects.get(pk=uid)
        except (TypeError, ValueError, OverflowError, User.DoesNotExist):
            raise serializers.ValidationError("Invalid token or user.")

        token_generator = PasswordResetTokenGenerator()
        if not token_generator.check_token(self.user, data['token']):
            raise serializers.ValidationError("Invalid or expired token.")
        
        return data

    def save(self, **kwargs):
        self.user.set_password(self.validated_data['new_password'])
        self.user.save()
        return self.user


class ChangePasswordSerializer(serializers.Serializer):
    current_password = serializers.CharField(write_only=True)
    new_password = serializers.CharField(write_only=True, min_length=8, validators=[validate_password])
    re_new_password = serializers.CharField(write_only=True, min_length=8)

    def validate(self, data):
        user = self.context['request'].user

        # Check if the current password is correct
        if not user.check_password(data['current_password']):
            raise serializers.ValidationError({"current_password": "Current password is incorrect."})

        # Check if new password and confirmation match
        if data['new_password'] != data['re_new_password']:
            raise serializers.ValidationError({"new_password": "The two password fields didn’t match."})

        return data

    def save(self):
        user = self.context['request'].user
        user.set_password(self.validated_data['new_password'])
        user.save()
        return user