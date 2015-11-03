package puntoAtencion;

import uniandes.gload.core.Task;
import uniandes.gload.examples.clientserver.Client;

public class ClientServerTask extends Task{

	@Override
	public void execute() {
		PuntoAtencion puntoAtencion = new PuntoAtencion("172.24.100.31", 443, PuntoAtencion.HMACSHA256, 4);
		try {
			puntoAtencion.procesar();
		} catch (Exception e) {
		}	
	}
	
	@Override
	public void fail() {
		System.out.println(Task.MENSAJE_FAIL);
	}

	@Override
	public void success() {
		System.out.println(Task.OK_MESSAGE);
	}
}
