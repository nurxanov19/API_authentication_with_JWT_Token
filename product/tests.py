from django.test import TestCase

from rest_framework.test import APITestCase
from django.urls import reverse
from django.contrib.auth.models import User
from rest_framework import status
from rest_framework_simplejwt.tokens import RefreshToken


class ProductTest(APITestCase):

    def setUp(self):
        self.user = User.objects.create_user(username='nurxonov', password='shohjahon')
        refresh = RefreshToken.for_user(self.user)

        self.access_token = str(refresh.access_token)

        self.product_data = {
            'user': self.user,
            'title': 'Google pixel 9',
            'price': 700,
            'desc': 'Best phone with most advance camera'
        }

        self.create_product = reverse('create-product')     # CRUD amallari bajarilgan view lar
        self.list_product = reverse('list-product')

        self.client.post(self.create_product, self.product_data)

    def test_createProduct(self):
        self.client.credentials(HTTP_AUTHORIZATION='Bearer' + self.access_token)
        response = self.client.post(self.create_product, self.product_data)

        self.assertEqual(response.data['title'], 'Google pixel 9')

        ...


