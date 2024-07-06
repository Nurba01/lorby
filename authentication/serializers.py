from rest_framework import serializers
from authentication.models import User
import re


class UserRegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, required=True)
    password_confirm = serializers.CharField(write_only=True, required=True)

    class Meta:
        model = User
        fields = ['id', 'email', 'username', 'password', 'password_confirm']

    def validate(self, attrs):
        if attrs['password'] != attrs['password_confirm']:
            raise serializers.ValidationError({'password': "Password fields didn't match."})

        password = attrs['password']
        if not re.search(r'[A-Z]', password):
            raise serializers.ValidationError({'password': "Password must contain at least one uppercase letter."})
        if not re.search(r'[!@#$%^&*]', password):
            raise serializers.ValidationError(
                {'password': "Password must contain at least one special character (!@#$%^&*)."})
        if len(password) < 8:
            raise serializers.ValidationError({'password': "Password must be at least 8 characters long."})

        return attrs


class ConfirmationCodeSerializer(serializers.Serializer):
    code = serializers.CharField(max_length=6)


class LoginSerializer(serializers.ModelSerializer):
    password = serializers.CharField(
        write_only=True,
        required=True,
        style={'input_type': 'password', 'placeholder': 'Password'}
    )

    class Meta:
        model = User
        fields = [
            "username",
            "password",
        ]


class LogoutSerializer(serializers.Serializer):
    refresh_token = serializers.CharField()


class EmailSerializer(serializers.Serializer):
    email = serializers.EmailField()
