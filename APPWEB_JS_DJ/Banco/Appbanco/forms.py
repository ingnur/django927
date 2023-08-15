# forms.py
from typing import Any
from django import forms
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth import get_user_model
from django.contrib.auth.forms import AuthenticationForm
from .models import User


User = get_user_model() # para obtener el modelo de usuario personalizado que se está utilizando en el proyecto. Almacenamos este modelo en la variable User para poder referenciarlo en el formulario.

class UserForm(UserCreationForm):#Esta clase nos ayudará a crear un formulario de registro personalizado para los usuarios.
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['documento'].widget.attrs.update({
            'required':'',
             'name':'doc',
             'id':'doc',
             'type':'text',
             'class':'form-input',
             'placeholder':'Documento',
             'maxlength':'20',
             'minlength':'1'

        })
        self.fields['username'].widget.attrs.update({
            'required':'',
             'name':'username',
             'id':'username',
             'type':'text',
             'class':'form-input',
             'placeholder':'Usario',
             'maxlength':'20',
             'minlength':'5'

        })
        self.fields['email'].widget.attrs.update({
            'required':'',
             'name':'email',
             'id':'email',
             'type':'email',
             'class':'form-input',
             'placeholder':'tucorre@correo.com',
             'maxlength':'20',
             'minlength':'5'

        })
        self.fields['password1'].widget.attrs.update({
            'required':'',
             'name':'pass',
             'id':'pass',
             'type':'password',
             'class':'form-input',
             'placeholder':'password',
             'maxlength':'20',
             'minlength':'8'

        })
        self.fields['password2'].widget.attrs.update({
            'required':'',
             'name':'pass2',
             'id':'pass2',
             'type':'password',
             'class':'form-input',
             'placeholder':'Confirmar password',
             'maxlength':'20',
             'minlength':'8'

        })
        self.fields['rol'].widget.attrs.update({
            'required':'',
             'name':'rol',
             'id':'rol',
             'type':'text',
             'class':'form-input',
             'placeholder':'Rol',
             'maxlength':'10',
             'minlength':'3'

        })
        self.fields['imagen'].widget.attrs.update({
          
             'name':'img',
             'id':'img',
             'type':'file',
             'class':'form-input',
             
             

        })
    rol = forms.CharField(max_length=100)
    imagen = forms.ImageField(required=False)
    documento = forms.CharField(max_length=30)


     

    class Meta:
        model = User
        fields = ['documento', 'username', 'email', 'password1', 'password2', 'rol', 'imagen']








'''class ClienteForm(UserCreationForm):#Esta clase nos ayudará a crear un formulario de registro personalizado para los usuarios.
    documento = forms.CharField(max_length=30)
    nombre= forms.CharField(max_length=100)
    apellido= forms.CharField(max_length=100)
    correo= forms.CharField(max_length=100)
    celular= forms.CharField(max_length=100)
   
    

    class Meta:
        model = User  #para que el formulario sepa a qué modelo está vinculado y pueda funcionar correctamente con las vistas y modelos relacionados.
        fields = ['documento','nombre', 'apellido', 'correo', 'celular']'''
       

class LoginForm(AuthenticationForm):
    class Meta:
        model = User
        fields = ['username', 'password']
        