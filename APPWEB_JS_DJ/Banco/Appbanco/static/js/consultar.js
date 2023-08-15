
function consultar(){
  alert("sus clientes")
// Realizar la solicitud GET con fetch
  fetch("http://127.0.0.1:8000/cliente", {
  method: "GET",
  headers: {
    "Content-Type": "application/json"
  }
})
.then(response => response.json())
.then(datos => {
  // Procesar la respuesta del servidor
  console.log("hola")
  console.log(datos);

  // Obtener la referencia a la tabla
  var tabla = document.getElementById("tablaClientes");

  // Limpiar el contenido de la tabla
  tabla.innerHTML = "";

  // Recorrer los datos y agregar las filas a la tabla
  console.log(datos);
 
      tabla.innerHTML = '';
       if(datos===0){
        tabla.innerHTML +=`<div id="sinmensajes"> No tienes mensajes </div>`
    }
      for(let dato of datos){
       
      //CARGA LOS MENSAJES QUE EL PADRE ENVIA Y DA LA OPCION DE RESPONDER est=2 SON MENSAJES QUE NO SE HAN REPONDIDO Y DA LA OPCION DE REPONDER
    
      tabla.innerHTML +=`
      <tr>
        <td>  ${dato.documento} </td>
        <td>  ${dato.nombre} </td>
        <td>  ${dato.apellido} </td>
        <td>  ${dato.correo} </td>
        <td>  ${dato.celular} </td>
                            
                                   
        </tr>`;

                                          
          }
});

}

consultar();