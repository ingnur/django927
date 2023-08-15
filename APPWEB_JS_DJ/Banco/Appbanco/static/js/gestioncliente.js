document.addEventListener("DOMContentLoaded", function() {
    document.getElementById("frminsertar").addEventListener("submit", function(event) {
        //event.preventDefault();  // Evitar el envío del formulario por defecto

        // Capturar los datos del formulario
        var data = new FormData(this);

        /*var formDataObj = {};
        for (var key of data.keys()) {
            formDataObj[key] = data.get(key);
        }*/

        // Convertir el objeto a una cadena JSON y mostrarlo en la consola
       // var jsonData = JSON.stringify(formDataObj);
       // console.log(jsonData);
        console.log(data.get("nombre"));
        // Realizar la solicitud POST con fetch
        fetch("http://127.0.0.1:8000/insertar/", {
            method: "POST",
           // body: formData
            body: data 
          /* body: JSON.stringify({
            documento: "34",
            nombre: "e",
            apellido: "e",
            correo: "e",
            celular: "2"
        }),*/
       /* headers: {
            "Content-Type": "application/json"
        }*/




        })
        .then(response => response.json())
        .then(data => {
            console.log("este es la respuesta",data)
            // Procesar la respuesta del servidor
            if(data=='Datos insertados correctamente'){
             swal("Datos Registrados", "", "success");

            }

            else if (data=='El documento ya existe en la base de datos'){
                swal("El documento Ya existe", "", "success");
            }

            else if(data=='Todos los campos deben ser completados'){
                swal("Verifica todos los campos", "", "success");
            }
        })
        .catch(error => {
            console.error("Error:", error);
        });
    });
});