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
from django.core.exceptions import ValidationError


'''def  principal (request):
    listacliente=Cliente.objects.all()
    #listaclientes=Cliente.objects.all()[:2]
    #listaclienete=Cliente.objects.all()[2:4]
    #listacliente=Cliente.objects.all().order_by('nombreuno')
    #listacliente=Cliente.objects.all().order_by('-nombreuno')
    #listacliente=Cliente.objects.filter(nombreuno='Pepe')
    #listacliente=Cliente.objects.filter(nombreuno='Maria',nombredos='Ana')
    #listacliente=Cliente.objects.filter(nombreuno='Pepe')
    #listacliente=Cliente.objects.filter(edad__gte=20)
    #listacliente=Cliente.objects.filter(edad__lte=20)
    #listacliente=Cliente.objects.filter(nombreuno__startswith='P')
    #listacliente=Cliente.objects.filter(nombreuno__contains='a')
    return render(request,"index.html",{"cli":listacliente})'''

class ListaCliente(View):
    @method_decorator(login_required)
    def get(self,request):
        datos=Cliente.objects.all()
        #datoscli=list(datos)
        #return JsonResponse(datoscli, safe=False)
        #return render(request, 'index.html', {'datoscli': datoscli})
        datos_clientes = []
        for cliente in datos:
         datos_clientes.append({
            'documento': cliente.documento,
            'nombre': cliente.nombre,
            'apellido': cliente.apellido,
            'correo': cliente.correo,
            'celular': cliente.celular
        })

        # Devolver los datos en formato JSON
        return JsonResponse(datos_clientes, safe=False)

class Insertarcliente(View):
    print("entro")
   
    @method_decorator(csrf_exempt)
    def dispatch(self, request, *args: Any, **kwargs):
        return super().dispatch(request, *args, **kwargs)
    

    #@method_decorator(login_required)
    def post(self, request):
         
        print("entrodos")
        try:
            # Decodificar los datos JSON recibidos
            datos = json.loads(request.body.decode('utf-8'))
        except (json.JSONDecodeError, UnicodeDecodeError):
            return JsonResponse({'error': 'EEEEEERRRRRROR al decodificar los datos JSON'})

      
        documento = datos.get('documento')
        nombre = datos.get('nombre')
        apellido = datos.get('apellido')
        correo = datos.get('correo')
        celular = datos.get('celular')
        Cliente.objects.create(documento=documento, nombre=nombre, apellido=apellido, correo=correo, celular=celular)
        print("ESTE ES EL DOCUMENTO",documento)

        if Cliente.objects.filter(documento=documento).exists():
            return JsonResponse({'mensaje': 'El documento ya existe en la base de datos'})

        # Validar campos no vacíos
        if not documento or not nombre or not apellido or not correo or not celular:
            return JsonResponse({'mensaje': 'Todos los campos deben ser completados'})
        try:
            Cliente.objects.create(documento=documento, nombre=nombre, apellido=apellido, correo=correo, celular=celular)
            
            return JsonResponse({'mensaje': 'Datos insertados correctamente'})
        except ValidationError as e:
            return JsonResponse({'error': str(e)})
        #request.POST.get('documento')
        #request.POST.get('nombre')
        #request.POST.get('apellido')
        #request.POST.get('correo')
        #request.POST.get('celular')
        #print("Datos del cliente", request.POST)
        #Cliente.objects.create(documento=documento,nombre=nombre,apellido=apellido,correo=correo,celular=cel)
      
        #Cliente.objects.create(documento=datos['documento'],nombre=datos['nombre'],apellido=datos['apellido'],correo=datos['correo'],celular=datos['celular'])
        #cli.save()
        return JsonResponse({'mensaje': 'Datos insertados correctamente'})
        #return render(request, 'registrocliente.html', {'mensaje': 'Datos guardados'})'''
       
    
class Actualizar(View):
     @method_decorator(csrf_exempt)
     def dispatch(self, request, *args: Any, **kwargs):
        return super().dispatch(request, *args, **kwargs)
     
     def put(self, request,pk):
         
         try: 
             registro=Cliente.objects.get(pk=pk)
         except Cliente.DoesNotExist:
             return JsonResponse({"Error":"El documento no existe "})
         data=json.loads(request.body)
         registro.nombre=data.get('nombre')
         registro.apellido=data.get('apellido')
         registro.correo=data.get('correo')
         registro.celular=data.get('celular')
         registro.save()
         return JsonResponse({"Mensaje": "Datos actualizados"})

class Eliminar( View):
    @method_decorator(csrf_exempt)
    def dispatch(self, request, *args: Any, **kwargs):
        return super().dispatch(request, *args, **kwargs)
    def delete(self, request, pk):
         try: 
             registro=Cliente.objects.get(pk=pk)
         except Cliente.DoesNotExist:
             return JsonResponse({"Error":"El documento no existe "})
         
   
         registro.delete()
         return JsonResponse({"Mensaje": "Datos eliminados"})

'''class Insertarcreditos(View):
    @method_decorator(csrf_exempt)
    def dispatch(self, request, *args: Any, **kwargs):
        return super().dispatch(request, *args, **kwargs)
    
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

        
        Credito.objects.create(documento=cliente, codigo=codigo, monto=monto, plazo=plazo )
        
        return JsonResponse({'mensaje': 'Datos insertados correctamente'})'''
    
@login_required
def frminsertar(request):
   return render(request,"registrocliente.html")

def frmprincipal(request):
   return render(request,"index.html")
def frmconsultar(request):
   return render(request,"consultarcli.html")





