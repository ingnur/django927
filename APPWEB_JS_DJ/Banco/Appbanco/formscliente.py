from django import forms
from .models import Cliente

class ClienteForm(forms.ModelForm):
    class Meta:
        model = Cliente
        fields = ['nombre', 'apellido', 'correo', 'celular']

        widgets = {
            'nombre': forms.TextInput(attrs={'id':'nom',}),
            'apellido': forms.TextInput(attrs={'id':'nom',}),
            'correo': forms.EmailInput(attrs={'id':'nom',}),
            'celular': forms.TextInput(attrs={'id':'nom',}),
            
        }

