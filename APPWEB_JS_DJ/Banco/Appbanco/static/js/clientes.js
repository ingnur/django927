document.addEventListener("DOMContentLoaded", function() {

    document.getElementById("frminsertar").addEventListener("submit", function(event) {
      event.preventDefault();  // Evitar el envío del formulario por defecto
    
      // Capturar los datos del formulario
      var data = {
        documento: document.getElementById("documento").value,
        nombre: document.getElementById("nombre").value,
        apellido: document.getElementById("apellido").value,
        correo: document.getElementById("correo").value,
        celular: document.getElementById("celular").value
      };
      //probamos si los datos se estan enviando
      console.log( document.getElementById("documento").value,document.getElementById("nombre").value,)
  
      // Convertir el objeto a una cadena JSON
      var jsonData = JSON.stringify(data);
  
      // Realizar la solicitud POST con fetch
      fetch("http://127.0.0.1:8000/insertar/", {
        method: "POST",
        body: jsonData,
        headers: {
          "Content-Type": "application/json"
        }
      })
      .then(response => response.json())
      .then(data => {
        // Procesar la respuesta del servidor
    
        console.log(data['mensaje']);
        if(data['mensaje']=="Datos insertados correctamente"){
        swal("Datos Guardados", "", "success");
        }
        else if (data['mensaje']=='El documento ya existe en la base de datos'){
          swal("El documento Ya existe", "", "warning");
      }

      else if(data['mensaje']=='Todos los campos deben ser completados'){
          swal("Verifica todos los campos", "", "warning");
      }
      else if ('error' in data) {
        // Mostrar el mensaje de error en una alerta o cualquier otro elemento HTML
        console.error(data['error']);
        swal("Error al insertar datos: " + data['error'], "", "error");
    }
      })
      .catch(error => {
        console.error(error);
      });

      //consultar();

    });

   // Importar archivo2.js


// Llamar a la función



  });




  