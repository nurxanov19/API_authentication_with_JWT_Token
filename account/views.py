from django.shortcuts import render

from django.contrib.auth.models import User
from rest_framework.permissions import IsAuthenticated
from rest_framework.views import APIView
from .serializers import RegisterSerializer
from rest_framework.response import Response
from rest_framework import status, generics
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework import permissions
from django.contrib.auth import authenticate, get_user_model
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.token_blacklist.models import BlacklistedToken, OutstandingToken


# class RegisterView(APIView):
#     def post(self, request):
#         serializer = RegisterSerializer(data=request.data)
#
#         if serializer.is_valid():
#             serializer.save()
#             return Response({"message": "User registered successfully"}, status=status.HTTP_201_CREATED)
#         return Response(data=serializer.data, status=status.HTTP_400_BAD_REQUEST)


class RegisterView(generics.CreateAPIView):
    queryset = User.objects.all()               # queryset is required by DRF's CreateAPIView base class for internal logic, even not being directly used in class
    # def get_queryset(self):           # instead of queryset, DRF asks for model you are using. So, one of queryset and get_queryset() must be given
    #     return User.objects.all()

    serializer_class = RegisterSerializer

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        self.perform_create(serializer)

        return Response(
            {"message": "Registration successful", "user": serializer.data},
            status=status.HTTP_201_CREATED
        )


class LoginView(APIView):

    def post(self, request):
        username = request.data.get('username')
        password = request.data.get('password')

        user = authenticate(username=username, password=password)

        if user is not None:
            refresh = RefreshToken.for_user(user)
            return Response(data={
                'refresh': str(refresh),
                'access': str(refresh.access_token)
            }, status=status.HTTP_200_OK)
        return Response({'Error': 'Not logged'}, status=status.HTTP_400_BAD_REQUEST)


class LogoutView(APIView):

    def post(self, request):
        try:
            refresh_token = request.data['refresh']
            token = RefreshToken(refresh_token)
            token.blacklist()
            return Response({'Message': 'You logged out successfully'})
        except Exception as e:
            return Response({'Error': 'Something went wrong '})


class ProfileView(APIView):
    authentication_classes = JWTAuthentication,
    permission_classes = [IsAuthenticated]
    def get(self, request):
        user = request.user
        return Response(data={'user': user.username}, status=status.HTTP_200_OK)


class PasswordChangeView(APIView):
    authentication_classes = JWTAuthentication,
    permission_classes = IsAuthenticated,

    def put(self, request):
        password = request.data.get('password')
        new_password = request.data.get('new_password')

        user = get_user_model().objects.get(pk=request.user.id)
        if not user.check_password(raw_password=password):
            return Response({'Error': 'Password did not mach, incorrect'}, status.HTTP_400_BAD_REQUEST)

        user.set_password(new_password)
        user.save()

        return Response({'Message': f'{user.username.title()}, Your password changed successfully'}, status=status.HTTP_200_OK)



