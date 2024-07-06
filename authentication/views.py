from rest_framework import status
from rest_framework.exceptions import AuthenticationFailed
from rest_framework.response import Response
from rest_framework import generics
from rest_framework.permissions import IsAuthenticated
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.views import (
    TokenRefreshView,
)
from drf_yasg.utils import swagger_auto_schema
from authentication.utils import Util
from authentication.serializers import (
    UserRegisterSerializer,
    ConfirmationCodeSerializer,
    LoginSerializer,
    LogoutSerializer,
    EmailSerializer,
)
from authentication.models import User, ConfirmationCode


class TokenRefreshView(TokenRefreshView):
    @swagger_auto_schema(
        tags=['Authentication'],
        operation_description="Этот эндпоинт предоставляет "
                              "возможность пользователю обновить "
                              "токен доступа (Access Token) с помощью "
                              "токена обновления (Refresh Token). Токен "
                              "обновления позволяет пользователям продлить "
                              "срок действия своего Access Token без "
                              "необходимости повторной аутентификации."
    )
    def post(self, *args, **kwargs):
        return super().post(*args, **kwargs)


class UserRegisterView(generics.CreateAPIView):
    queryset = User.objects.all()
    serializer_class = UserRegisterSerializer

    @swagger_auto_schema(
        tags=['Authentication'],
        operation_description="Этот эндпоинт позволяет пользователям "
                              "зарегистрироваться в системе. При успешной "
                              "регистрации, система создает нового пользователя, "
                              "отправляет код подтверждения на указанный адрес "
                              "электронной почты и возвращает сообщение об успешной регистрации.",
    )
    def post(self, request, *args, **kwargs):
        serializer = UserRegisterSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(data={
                'error': serializer.errors
            }, status=status.HTTP_406_NOT_ACCEPTABLE)

        username = request.data.get('username')
        email = request.data.get('email').lower()
        password = request.data.get('password')

        user = User.objects.create_user(
            email=email,
            username=username,
            password=password,
        )
        confirmation_code = ConfirmationCode.generate_code()
        ConfirmationCode.objects.create(user=user, code=confirmation_code)

        data = {
            "email_body": f'Your confirmation code: {confirmation_code}',
            "to_email": email,
            "email_subject": 'Confirmation Code',
        }

        Util.send_email(data)
        response_data = {
            "message": "User successfully registered. Confirmation code sent to your email.",
        }
        return Response(response_data, status=status.HTTP_201_CREATED)


class ResendConfirmationCodeView(generics.GenericAPIView):
    serializer_class = EmailSerializer

    @swagger_auto_schema(
        tags=['Authentication'],
        operation_description="Этот эндпоинт позволяет пользователю "
                              "запросить повторную отправку кода подтверждения "
                              "на указанный адрес электронной почты, если он "
                              "еще не подтвердил свою регистрацию.",
        request_body=EmailSerializer,
    )
    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data)
        if not serializer.is_valid():
            return Response(data={
                'error': serializer.errors
            }, status=status.HTTP_400_BAD_REQUEST)

        email = serializer.validated_data.get('email').lower()
        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            return Response(data={
                'error': 'User with this email does not exist.'
            }, status=status.HTTP_404_NOT_FOUND)

        confirmation_code = ConfirmationCode.objects.filter(user=user).first()
        if not confirmation_code:
            return Response(data={
                'error': 'No confirmation code found for this user.'
            }, status=status.HTTP_404_NOT_FOUND)

        if confirmation_code.is_confirmed:
            return Response(data={
                'message': 'User already confirmed.'
            }, status=status.HTTP_400_BAD_REQUEST)

        # Создаем новый код подтверждения
        new_confirmation_code = ConfirmationCode.generate_code()
        confirmation_code.code = new_confirmation_code
        confirmation_code.save()

        data = {
            "email_body": f'Your new confirmation code: {new_confirmation_code}',
            "to_email": email,
            "email_subject": 'New Confirmation Code',
        }

        Util.send_email(data)
        return Response(data={
            'message': 'New confirmation code resent to your email.'
        }, status=status.HTTP_200_OK)


class ConfirmCodeView(generics.GenericAPIView):
    serializer_class = ConfirmationCodeSerializer

    @swagger_auto_schema(
        tags=['Authentication'],
        operation_description="Этот эндпоинт предоставляет возможность "
                              "пользователю подтвердить свой аккаунт, "
                              "введя корректный код подтверждения, который "
                              "был отправлен на указанный адрес электронной "
                              "почты после регистрации.",
    )
    def post(self, request):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        code = serializer.validated_data.get('code')
        try:
            confirmation_code = ConfirmationCode.objects.get(code=code)
        except ConfirmationCode.DoesNotExist:
            return Response({"error": "Invalid or already confirmed code."}, status=400)

        user = confirmation_code.user
        user.is_verified = True
        user.save()
        confirmation_code.delete()
        return Response({
            "message": "You successfully verified your account!",
        }, status=200)


class LoginView(generics.GenericAPIView):
    serializer_class = LoginSerializer

    @swagger_auto_schema(
        tags=['Authentication'],
        operation_description="Этот эндпоинт предоставляет "
                              "возможность пользователю войти в "
                              "систему, предоставив имя пользователя "
                              "и пароль. В случае успешного входа, система "
                              "генерирует Access Token и Refresh Token для "
                              "пользователя, которые можно использовать для "
                              "доступа к защищенным ресурсам. \nСрок действия 'access' токена - "
                              "60 минут, а refresh токена - 30 дней.",
    )
    def post(self, request):
        if "username" not in request.data or "password" not in request.data:
            return Response({"error": "Username and password are required in the request data."},
                            status.HTTP_400_BAD_REQUEST)

        username = request.data["username"]
        password = request.data["password"]

        user = User.objects.filter(username=username).first()

        if user is None:
            return Response({"error": "User not found!"}, status.HTTP_404_NOT_FOUND)
        if not user.check_password(password):
            raise AuthenticationFailed({"error": "Incorrect password!"})
        if not user.is_verified:
            raise AuthenticationFailed({"error": "Email is not verified!"})

        refresh = RefreshToken.for_user(user)

        return Response(
            {
                "refresh": str(refresh),
                "access": str(refresh.access_token),
            }
        )


class LogoutView(generics.GenericAPIView):
    serializer_class = LogoutSerializer
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        tags=['Authentication'],
        operation_description="Этот эндпоинт предоставляет "
                              "возможность пользователю выйти из "
                              "системы, деактивировав Refresh Token. "
                              "После успешного выхода, Refresh Token "
                              "пользователя больше не будет действителен, "
                              "и пользователь потеряет доступ к защищенным ресурсам.",
    )
    def post(self, request):
        serializer = LogoutSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        refresh_token = serializer.validated_data["refresh_token"]

        try:
            token = RefreshToken(refresh_token)
            token.blacklist()
            return Response({"message": "You have successfully logged out."}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({"error": "Unable to log out."}, status=status.HTTP_400_BAD_REQUEST)
