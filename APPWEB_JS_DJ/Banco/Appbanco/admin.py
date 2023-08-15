from django.contrib import admin
from .models import Cliente,Credito,LineasCredito


@admin.register(Cliente)
class ClienteA(admin.ModelAdmin):
   list_display=('documento','nombre','apellido')

@admin.register(LineasCredito)
class LineasCreditoA(admin.ModelAdmin):
   list_display=('codigo','nombre')

@admin.register(Credito)
class CreditoA(admin.ModelAdmin):
   list_display=('id','monto')
