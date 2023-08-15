from django.urls import path
from .views import ListaCliente,Insertarcliente,Actualizar,Eliminar
from .viewscre import Insertarcreditos,ListaCreditos
from .viewsLogin import RegistrarUsuarioView,IniciarSesionView,PerfilClienteView
from . import views,viewscre,viewsLogin
from django.contrib.auth.decorators import login_required
from django.conf import settings
from django.conf.urls.static import static

urlpatterns=[
    path('cliente',ListaCliente.as_view(), name='Clientes'),
    path('credito',ListaCreditos.as_view(), name='credito'),
    path('insertar/',Insertarcliente.as_view(), name='insertar'),
    path('insertarc',Insertarcreditos.as_view(), name='insertarc'),
    path('actualizar/<pk>',Actualizar.as_view(), name='actualizar'),
    path('eliminar/<pk>',Eliminar.as_view(), name='eliminar'),
    path('frminsertar/',views.frminsertar, name="registrar" ),
    path('frminsertar/',views.frminsertar, name="registrar" ),
    path('frmconsultar',views.frmconsultar, name="registrarcredito" ),
    #path('frmusuario/',viewsLogin.frm, name="registrarusuario" ),
    path('registro/',RegistrarUsuarioView.as_view(), name='registrar_usuario'),
    path('iniciar_sesion/', IniciarSesionView.as_view(), name='iniciar_sesion'),
   # path('frmcliente/<str:cliente_id>/',viewsLogin.frmcliente, name="frmcliente" ),
    path('frmcliente/', viewsLogin.IniciarSesionView.as_view(), name='frmcliente'),
    path('frmdatcliente/',viewsLogin.frmdatcliente, name="frmdatcliente" ),
    path('frmempleado/',viewsLogin.frmempleado, name="frmempleado" ),
    path('',views.frmprincipal, name="frmprincipal" ),
    path('perfil-cliente/', PerfilClienteView.as_view(), name='perfil_cliente'),

   
] + static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)