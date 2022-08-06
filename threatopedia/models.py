from django.db import models

# Create your models here.

class Result(models.Model):
	ip = models.CharField(max_length=20, blank=True, null=True)
	
