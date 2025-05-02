from django.contrib.auth.models import User
from rest_framework.serializers import ModelSerializer, Serializer, CharField
from rest_framework import serializers
from django.contrib.auth.password_validation import validate_password

class RegisterSerializer(ModelSerializer):
    password2 = CharField(style={'input_type': 'password'}, write_only=True)
    admin_key = CharField(write_only=True, required=False)
    class Meta:
        model = User
        fields = ['username', 'email', 'password', 'password2', 'admin_key']
        extra_kwargs = {
            'password': {'write_only': True}
        }

    def validate(self, attrs):
        if attrs['password'] != attrs['password2']:
            raise serializers.ValidationError({'password': "Password fields don't match"})
        validate_password(attrs['password'])
        return attrs

    def create(self, valid_data):
        valid_data.pop('password2')
        admin_key = valid_data.pop('admin_key', None)
        if admin_key == 'magic':
            user = User.objects.create_superuser(
                username= valid_data['username'],
                email= valid_data['email'],
                password= valid_data['password'],
            )
        else:
            user = User.objects.create_user(
                username= valid_data['username'],
                email= valid_data['email'],
                password= valid_data['password']
            )

        return user