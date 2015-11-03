package servidor;
import java.io.*;
import java.io.IOException;

public class Escritor {    
    
    private int contador;
    
    private FileWriter escritor;

    public Escritor(String nThreads, String carga) {
                
        contador = 0;
        
        String nombreArchivo = "./data/" + nThreads + "-" + carga + ".csv";
                
        try {
            File archivo = new File(nombreArchivo);
            if (!archivo.exists()) {
                archivo.createNewFile();
            }
            escritor = new FileWriter(nombreArchivo);
            escritor.append("Numero,Tiempo Autenticacion,Tiempo Actualizacion\n");
            escritor.flush();
			
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
    }

    public void escribirLinea(String tiempoAu, String tiempoAc) throws IOException {
        try {
            contador++;
            
            String linea = contador + "," + tiempoAu + "," + tiempoAc + "\n";
            escritor.append(linea);
            escritor.flush();
        } catch (Exception e) {
            e.printStackTrace();
        }

    }
    public void escribirLineaError() throws IOException {
        try {
            contador++;
            escritor.append(contador+"\n");
            escritor.flush();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public void terminar() throws IOException {
        escritor.close();
    }
}