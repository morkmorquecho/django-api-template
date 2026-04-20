from django.db import models
from core.models import BaseModel 
from django.contrib.auth.models import AbstractUser
from users.utils import phone_regex
import uuid

class User(AbstractUser):
    email = models.EmailField(unique=True) 
    REQUIRED_FIELDS = ['email']

class Address(BaseModel):
    user = models.ForeignKey(User, on_delete=models.CASCADE) 
    recipient_name = models.CharField(max_length=200)    
    country = models.CharField(max_length=50, choices=[
        ('mexico', 'Mexico'),
        ('usa', 'Estados Unidos'),
        ('canada', 'Canada')])
    state = models.CharField(max_length=100) 
    city = models.CharField(max_length=100)
    postal_code = models.CharField(max_length=20)
    neighborhood = models.TextField()
    street = models.TextField()
    street_number = models.IntegerField()
    phone_number = models.CharField(validators=[phone_regex], max_length=20)
    reference = models.TextField()
    apartment_number = models.CharField(max_length=20, blank=True, null=True)
    is_default = models.BooleanField(default=False)
    
    def __str__(self):
        return f"{self.street} {self.street_number}, {self.city}"