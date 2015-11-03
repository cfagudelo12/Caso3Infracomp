package puntoAtencion;

import uniandes.gload.core.LoadGenerator;
import uniandes.gload.core.Task;

public class Generator {
	
	private LoadGenerator generator;
	
	public Generator() {
		Task work = createTask();
		int numberOfTasks = 200;
		int gapBetweenTasks = 40;
		generator= new LoadGenerator("Client - Server Load Test", numberOfTasks, work, gapBetweenTasks);
		generator.generate();
	}
	
	private Task createTask() {
		return new ClientServerTask();
	}
	

	public static void main(String[] args) {
		@SuppressWarnings("unused")
		Generator gen = new Generator();
	}

}
