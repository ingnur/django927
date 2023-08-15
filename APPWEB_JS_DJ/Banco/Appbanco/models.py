from django.contrib.auth.models import User
from django.contrib.auth.models import AbstractUser
from django.db import models
from django.conf import settings
from .enum import plazo

opc=[
    [0,'Cliente'],
    [1,'Empleado']
]

'''class Cliente(models.Model):
    #documento=models.OneToOneField(User,on_delete=models.CASCADE,max_length=30,primary_key=True)
    documento=models.TextField(max_length=30, null=False,primary_key=True)
    nombre=models.TextField(max_length=30)
    apellido=models.TextField(max_length=30)
    correo=models.TextField(max_length=30)
    celular=models.TextField(max_length=30)
    #user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='cliente_rel', null=True, blank=True)  # Agregamos related_name
    user = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='cliente', null=True, blank=True)
class User(AbstractUser):
    rol = models.CharField(max_length=100)
    imagen = models.ImageField(default='dos.png',upload_to='user_images/', null=True, blank=True)
    documento=models.TextField(max_length=30, primary_key=True)

    def __str__(self):
        return self.username'''

 

class Cliente(models.Model):
 
    documento = models.TextField(max_length=30, primary_key=True,null=False)
    nombre = models.TextField(max_length=30,blank=True)
    apellido = models.TextField(max_length=30,blank=True)
    correo = models.TextField(max_length=30,blank=True)
    celular = models.TextField(max_length=30,blank=True)
    
class User(AbstractUser):
    rol = models.CharField(max_length=100)
    #imagen = models.ImageField(default='img/dos.png', upload_to='img', null=True, blank=True)
    #imagen = models.ImageField(default='img/dos.png', null=True, blank=True)
    imagen = models.ImageField(upload_to='img/', null=True, blank=True)

    documento = models.OneToOneField(Cliente, on_delete=models.CASCADE, primary_key=True)


class  LineasCredito(models.Model):
    codigo=models.PositiveSmallIntegerField(primary_key=True,verbose_name="Código")
    nombre=models.TextField(max_length=30)
    montomaximo=models.PositiveBigIntegerField(verbose_name="Monto maximo")
    plazomaximo=models.PositiveSmallIntegerField(verbose_name="Plazo maximo")

class Credito(models.Model):
    documento=models.ForeignKey(Cliente, null=False, on_delete=models.CASCADE)
    codigo=models.ForeignKey(LineasCredito,null=False,on_delete=models.CASCADE)
    monto=models.PositiveBigIntegerField(verbose_name="Total credito")
    plazo=models.PositiveSmallIntegerField(verbose_name="Plazo",choices=plazo,default=6)
