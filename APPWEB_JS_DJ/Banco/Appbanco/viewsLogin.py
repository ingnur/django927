from django.shortcuts import render, redirect
from django.views import View
from .forms import UserForm
from .formscliente import ClienteForm
from Appbanco.models import Cliente,User
#login
from django.contrib.auth import authenticate, login
from django.views import View
from .forms import LoginForm
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt
from typing import Any
from django.contrib import messages
import json
from django.contrib.auth.decorators import login_required
from django.utils.decorators import method_decorator


'''class RegistrarUsuarioView(View):
    def get(self, request):#esto es para poder ver el formulario de registro
        form = UserForm()#instanciamos para crear un formulario en blanco
        return render(request, 'login.html', {'form': form})# es para que el usuario pueda ver el frm de registro
    @method_decorator(csrf_exempt)
    def dispatch(self, request, *args: Any, **kwargs):
        return super().dispatch(request, *args, **kwargs)                                         #un diccionario para pasar eñ contexto del formulario
    def post(self, request):
        
        form = UserForm(request.POST)
        if form.is_valid():
            form.save()
            return redirect('iniciar_sesion')
        return render(request, 'iniciosesion.html', {'form': form})'''
    
#class RegistrarUsuarioView(View):
'''  template_name = 'login.html'

    @method_decorator(csrf_exempt)
    def dispatch(self, request, *args: Any, **kwargs):
        return super().dispatch(request, *args, **kwargs)

    def get(self, request):
        form = UserForm()
        return render(request, self.template_name, {'form': form})

    def post(self, request):
        if request.method == 'POST':
            print("Datos recibidos desde Flutter:")
            print("Documento:", request.POST.get('Documento'))
            print("Username:", request.POST.get('Username'))
            print("Email:", request.POST.get('Email'))
            print("Password1:", request.POST.get('Password1'))
            print("Password2:", request.POST.get('Password2'))
            print("Rol:", request.POST.get('Rol'))
            print("Imagen:", request.FILES.get('Imagen'))  # Si
            form = UserForm(request.POST)
            if form.is_valid():
                print("Datos recibidos desde Flutter:")
                print("Documento:", form.cleaned_data['Documento'])
                print("Username:", form.cleaned_data['Username'])
                print("Email:", form.cleaned_data['Email'])
                print("Password1:", form.cleaned_data['Password1'])
                print("Password2:", form.cleaned_data['Password2'])
                print("Rol:", form.cleaned_data['Rol'])
                print("Imagen:", request.FILES.get('Imagen'))  # Si estás enviando una imagen desde Flutter


                form.save()
                messages.success(request, 'Usuario registrado correctamente.')
                return redirect('iniciar_sesion')
            else:
                print("ERROdosssssss")
                messages.error(request, 'Error al registrar el usuario.')
        else:
            form = UserForm()
            print("eeror UNO")
        return render(request, self.template_name, {'form': form})'''
''' def post(self, request):
     if request.method == 'POST':
        try:
            data = json.loads(request.body)
            print("Datos recibidos desde Flutter Unoooo:")
            print(data)  # Imprime los datos recibidos desde Flutter
            form = UserForm(data)
            print("Errores del formulario:")
            print(form.errors)
            if form.is_valid():
                print("Datos válidos:")
                print(form.cleaned_data) 

                form.save()
                messages.success(request, 'Usuario registrado correctamente.')
                return redirect('iniciar_sesion')
            else:
                print("NOOOOOO ENTRA")
                messages.error(request, 'Error al registrar el usuario.')
        except json.JSONDecodeError:
            messages.error(request, 'Error en los datos enviados desde Flutter.')
     else:
        form = UserForm()
     return render(request, self.template_name, {'form': form})'''
  


  # views.py


class RegistrarUsuarioView(View):
   
    template_name = 'login.html'
    
    @method_decorator(csrf_exempt)
    def dispatch(self, request, *args, **kwargs):
        return super().dispatch(request, *args, **kwargs)
    
    def post(self, request):
        #if not request.user.is_authenticated:
         #   return redirect('iniciar_sesion')  
        #form = UserForm()  # Definir form con un valor predeterminado
        form = UserForm(request.POST)  # Agregar request.FILES
        
        if request.method == 'POST':
            print("en el metodod")
            #if request.headers.get('content-type') == 'application/json':
            if 'application/json' in request.headers.get('content-type', ''):
                print("en el json")
                self.handle_flutter_data(request)
            else:
                print("Esta en django")
                form = UserForm(request.POST)
                print("Contenido de request.POST:")
                print(request.POST)
                print("Contenido de request.FILES:")
                print(request.FILES)

                                
                if form.is_valid():
                 print("iiiiiii")
                 if form.cleaned_data['imagen'] or form.cleaned_data['imagen'] is None:
                    print("eeeeeeeeee")
                   
                    form.save()
                    imagen_file = request.FILES['imagen']

                    # Crear una instancia del modelo User con los datos del formulario
                    user_instance = form.save(commit=False)
                    user_instance.imagen = imagen_file  # Asignar la imagen al campo correspondiente en el modelo
                    user_instance.save()                   

                    messages.success(request, 'Usuario registrado correctamente desde formulario HTML.')
                    return redirect('iniciar_sesion')
                else:
                    print("EEEERRRRR",form.errors)
                    messages.error(request, 'Error al registrar el usuario desde formulario HTML.')
        else:
            print("no metodo")
            form = UserForm()
        return render(request, self.template_name, {'form': form})

    def get(self, request):
        form = UserForm()
        return render(request, self.template_name, {'form': form})


#Para flutter
    def handle_flutter_data(self, request):
        try:
            data = json.loads(request.body)
            print("Datos recibidos desde Flutter:")
            print(data)  # Imprime los datos recibidos desde Flutter
            form = UserForm(data)
            if form.is_valid():
                print("Datos válidos:")
                print(form.cleaned_data)  # Imprime los datos validados por el formulario
                form.save()
                messages.success(request, 'Usuario registrado correctamente desde Flutter.')
            else:
                print("Errores en el formulario:")
                print(form.errors)  
        except json.JSONDecodeError:
            messages.error(request, 'Error en los datos enviados desde Flutter.')





'''class IniciarSesionView(View):
    def get(self, request):
        form = LoginForm()
        #print(form)
        return render(request, 'iniciosesion.html', {'form': form})

    def post(self, request):
        form = LoginForm(data=request.POST)

        if form.is_valid():
            username = form.cleaned_data.get('username')
            password = form.cleaned_data.get('password')

            # Autenticar al usuario solo con el username y la password
            datt = authenticate(username=username, password=password)

            if datt is not None:
                login(request, datt)

                if datt.rol == 'Cliente':
                    try:
                        # Obtener el campo documento del modelo Cliente
                        documento = datt.documento_id
                        print("DDDDDDDDDDDD",documento)

                        # Consultar los datos del cliente utilizando el campo documento
                        cliente = Cliente.objects.get(documento=documento)
                        print("******", request.method)
                        print(request.POST)

                        if request.method == 'POST' and 'editar' in request.POST:
                                    
                           # print("Entrando a Clientes POST")
                            # Procesar el formulario si se envió con el botón "Guardar cambios"
                         form = UserForm(request.POST)
                         if form.is_valid():
                            cliente_form = ClienteForm(request.POST, instance=cliente)
                            if cliente_form.is_valid():
                                print("EN EL IF DE LA VALIDACIO")
                                cliente_form.save()
                                messages.success(request, 'Cambios guardados correctamente.')
                                return redirect('cliente')
                            else:
                                print("error")
                                messages.error(request, 'Por favor, corrige los errores del formulario.')
                        else:
                            cliente_form = ClienteForm(instance=cliente)
                        return render(request, 'cliente.html', {'cliente': cliente, 'form': cliente_form})
                    except Cliente.DoesNotExist:
                        messages.error(request, 'No se encontraron los datos del cliente.')
                else:
                    return redirect('frmempleado')

            form.add_error(None, 'Credenciales inválidas. Por favor, intenta nuevamente.')

        return render(request, 'iniciosesion.html', {'form': form})'''



class IniciarSesionView(View):
    def get(self, request):
        form = LoginForm()
        return render(request, 'iniciosesion.html', {'form': form})

    def post(self, request):
        form = LoginForm(data=request.POST)

        if form.is_valid():
            username = form.cleaned_data.get('username')
            password = form.cleaned_data.get('password')
            user = authenticate(username=username, password=password)

            if user is not None:
                login(request, user)
                if user.rol == 'Cliente' or user.rol=='cliente':
                    return redirect('perfil_cliente')  
                else:
                    return redirect('frmempleado')
            else:
                form.add_error(None, 'Credenciales inválidas. Por favor, intenta nuevamente.')

        return render(request, 'iniciosesion.html', {'form': form})


@method_decorator(login_required(login_url='login'), name='dispatch')
class PerfilClienteView(View):
    template_name = 'cliente.html'

    def get(self, request):
        try:
            
            #print("ssssssssssssssss",request.user.documento_id)
            cliente = Cliente.objects.get(documento=request.user.documento_id)
            usuario = request.user
            print(usuario.imagen)
            #print("Datos del cliente:", cliente.documento, cliente.nombre, cliente.apellido, cliente.correo, cliente.celular)
        except Cliente.DoesNotExist:
            messages.error(request, 'No se encontraron los datos del cliente.')
            return redirect('iniciar_sesion')

        form = ClienteForm(instance=cliente)
       # print("aaaaaaaaaaa",form.nombre)
        return render(request, self.template_name, {'form': form, 'cliente': cliente,'usuario': usuario})

    def post(self, request):
        try:
            cliente = Cliente.objects.get(documento=request.user.documento_id)
        except Cliente.DoesNotExist:
            messages.error(request, 'No se encontraron los datos del cliente.')
            return redirect('iniciar_sesion')

        form = ClienteForm(request.POST, instance=cliente)

        if form.is_valid():
            form.save()

            messages.success(request, 'Cambios guardados correctamente.')
            return redirect('perfil_cliente')

        return render(request, self.template_name, {'form': form, 'cliente': cliente})


def frmdatcliente(request):
     return render(request,"cliente.html")

@login_required
def frmempleado(request):
     return render(request,"empleado.html")








