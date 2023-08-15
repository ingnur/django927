document.addEventListener("DOMContentLoaded", function() {

    document.getElementById("frmlogin").addEventListener("submit", function(event) {
      event.preventDefault();  // Evitar el envío del formulario por defecto
    
      // Capturar los datos del formulario
      var data = {
       
        use: document.getElementById("username").value,
        pass: document.getElementById("password").value,
        email: document.getElementById("email").value,
        
      };
      //probamos si los datos se estan enviando
      console.log( document.getElementById("username").value);
      console.log( document.getElementById("password").value);
      console.log( document.getElementById("email").value);
    
  
      // Convertir el objeto a una cadena JSON
      var jsonData = JSON.stringify(data);
  
      // Realizar la solicitud POST con fetch
      fetch("http://127.0.0.1:8000/insertaruser/", {
        method: "POST",
        body: jsonData,
        headers: {
          "Content-Type": "application/json"
        }
      })
      .then(response => response.json())
      .then(data => {
        // Procesar la respuesta del servidor
        console.log(data);
      })
      .catch(error => {
        console.error("Error:", error);
      });

      //consultar();

    });

   // Importar archivo2.js


// Llamar a la función



  });


