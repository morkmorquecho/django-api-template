from django.db import models
from core.models import BaseModel 
from django.core.validators import RegexValidator
from django.contrib.auth.models import AbstractUser

phone_regex = RegexValidator(
    regex=r'^\+?1?\d{9,15}$',
    message="Phone number must be entered in the format: '+999999999'. Up to 15 digits allowed."
)

class User(AbstractUser):
    email = models.EmailField(unique=True) 
    REQUIRED_FIELDS = ['email']


