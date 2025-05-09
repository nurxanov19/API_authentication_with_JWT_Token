from django.test import TestCase
from rest_framework import status

from rest_framework.test import APITestCase
from django.contrib.auth.models import User
from django.urls import reverse


class AuthTest(APITestCase):
    def setUp(self):        # Client yaratiladi
        self.register_url = reverse('register')
        self.login_url = reverse('login')
        self.logout_url = reverse('logout')
        self.profile_url = reverse('profile')
        self.password_change_url = reverse('password-change')

        self.user_data = {
            'username': 'sohib',
            'password': 'malik0000',
            'password2': 'malik0000',
            'email': 'hechqanday@gmail.com'
        }

        self.client.post(self.register_url, self.user_data)
        response = self.client.post(self.login_url, self.user_data)

        print("Register response:", self.client.post(self.register_url, self.user_data).data)
        print("Login response:", response.data)

        self.refresh_token = response.data['refresh']
        self.access_token = response.data['access']

    def test_register(self):
        data = {
            'username': 'nimagap',
            'password': 'salom1100',
            'password2': 'salom1100',
            'email': 'nimagap@gmail.com'
        }

        response = self.client.post(self.register_url, data)

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(response.data['user']['username'], 'nimagap')
        self.assertEqual(response.data['message'], 'Registration successful')

    def test_login(self):

        response = self.client.post(self.login_url, self.user_data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('refresh', response.data)
        self.assertIn('access', response.data)

    def test_logout(self):
        self.client.credentials(HTTP_AUTHORIZATION='Bearer ' + self.access_token )
        response = self.client.post(self.logout_url, {'refresh': self.refresh_token})

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['Message'], 'You logged out successfully')

    def test_profile(self):
        self.client.credentials(HTTP_AUTHORIZATION='Bearer ' + self.access_token)
        response = self.client.get(self.profile_url)

        self.assertEqual(response.status_code, 200)
        self.assertIn('user', response.data)
        self.assertEqual(response.data['user'], self.user_data['username'])

    def test_profile_fail(self):
        response = self.client.get(self.profile_url)

        self.assertEqual(response.status_code, 401)
        self.assertNotIn('Message', response.data)

    def test_password_change(self):
        self.client.credentials(HTTP_AUTHORIZATION='Bearer ' + self.access_token)
        data_change = {
            'password': 'malik0000',
            'new_password': 'nurxonov'
        }
        response = self.client.put(self.password_change_url, {'password': data_change['password'],
                                                               'new_password': data_change['new_password'] })
        print("Status:", response.status_code)
        print("Data:", response.data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['Message'], f'Sohib, Your password changed successfully')

