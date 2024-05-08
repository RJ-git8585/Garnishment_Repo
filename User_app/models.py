# models.py
from django.contrib.auth.models import AbstractUser
from django.db import models



class CustomUser(AbstractUser):
    gender = models.CharField(max_length=10)
    contact_number = models.CharField(max_length=15)

    # Remove the custom related_name and use the default ones
    groups = models.ManyToManyField(
        'auth.Group',
        blank=True,
        related_name='customuser_set',
        verbose_name='groups',
        help_text='The groups this user belongs to. A user will get all permissions granted to each of their groups.',
    )
    user_permissions = models.ManyToManyField(
        'auth.Permission',
        blank=True,
        related_name='customuser_set',
        verbose_name='user permissions',
        help_text='Specific permissions for this user.',
    )

class Profile(models.Model):
    user = models.OneToOneField(CustomUser , on_delete=models.CASCADE)
    forget_password_token = models.CharField(max_length=100)
    created_at = models.DateTimeField(auto_now_add=True)



# Employer_Profile details

class Employer_Profile(models.Model):
    profile_id=models.IntegerField(max_length=20)
    employer_name = models.CharField(max_length=50)
    street_name=  models.CharField(max_length=50)
    city=  models.CharField(max_length=50)
    state=  models.CharField(max_length=50)
    country =models.CharField(max_length=50)
    zipcode =models.IntegerField(max_length=25)
    email =models.EmailField(max_length=30)
    number_of_employer=models.IntegerField(max_length=20)
    department=models.CharField(max_length=50)

    

