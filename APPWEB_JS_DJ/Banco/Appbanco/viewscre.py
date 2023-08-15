from typing import Any
from django import http
from django.shortcuts import render
from Appbanco.models import Cliente,LineasCredito,Credito
from django.views.generic import ListView,View
from django.http import JsonResponse
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt
import json
from django.shortcuts import get_object_or_404
from django.contrib.auth.decorators import login_required
from django.utils.decorators import method_decorator


class Insertarcreditos(View):
    @method_decorator(csrf_exempt)
    def dispatch(self, request, *args: Any, **kwargs):
        return super().dispatch(request, *args, **kwargs)
    @method_decorator(login_required)
    def post(self, request):
        try:
            # Decodificar los datos JSON recibidos
            datos = json.loads(request.body.decode('utf-8'))
        except (json.JSONDecodeError, UnicodeDecodeError):
            return JsonResponse({'error': 'Error al decodificar los datos JSON'})

         
        monto = datos.get('monto')
        plazo = datos.get('plazo')
        documento_id = datos.get('documento')
        codigo_id = datos.get('codigo')
        cliente = get_object_or_404(Cliente, documento=documento_id)
        codigo = get_object_or_404(LineasCredito, codigo=codigo_id)

        print(monto,plazo,documento_id,codigo_id)
        Credito.objects.create(documento=cliente, codigo=codigo, monto=monto, plazo=plazo )
        
        return JsonResponse({'mensaje': 'Datos insertados correctamente'})
class ListaCreditos(View):
    @method_decorator(login_required)
    def get(self,request):
        datos=Credito.objects.all()
        #datoscli=list(datos)
        #return JsonResponse(datoscli, safe=False)
        #return render(request, 'index.html', {'datoscli': datoscli})
        datos_clientes = []
        for cliente in datos:
         datos_clientes.append({
          
            'monto': cliente.monto,
            'plazo': cliente.plazo,
            'documento': cliente.documento,
            'codigo': cliente.codigo
        })
         
          # Devolver los datos en formato JSON
        return JsonResponse(datos_clientes, safe=False)
   
def frminsertarcredito(request):
   return render(request,"registrocredito.html")