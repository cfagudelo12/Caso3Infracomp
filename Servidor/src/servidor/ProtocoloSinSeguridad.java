package servidor;

import java.awt.FontFormatException;
import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.security.cert.CertificateNotYetValidException;

import com.sun.corba.se.impl.oa.poa.ActiveObjectMap.Key;

import utils.Seguridad;
import utils.Transformacion;

/**
 * Esta clase implementa el protocolo que se realiza al recibir una conexión de un cliente.
 * Infraestructura Computacional Universidad de los Andes. 
 * Las tildes han sido eliminadas por cuestiones de compatibilidad.
 * 
 * @author Michael Andres Carrillo Pinzon 	-  201320.
 * @author José Miguel Suárez Lopera 		-  201510.
 * @author Cristian Fabián Brochero 		-  201520.
 */
public class ProtocoloSinSeguridad {

	// ----------------------------------------------------
	// CONSTANTES DE CONTROL DE IMPRESION EN CONSOLA
	// ----------------------------------------------------
	public static final boolean SHOW_ERROR = true;
	public static final boolean SHOW_S_TRACE = true;
	public static final boolean SHOW_IN = true;
	public static final boolean SHOW_OUT = true;
	// ----------------------------------------------------
	// CONSTANTES PARA LA DEFINICION DEL PROTOCOLO
	// ----------------------------------------------------
	public static final String EMPEZAR = "EMPEZAR";
	public static final String OK = "OK";
	public static final String ALGORITMOS = "ALGORITMOS";
	public static final String RSA = "RSA";
	public static final String HMACMD5 = "HMACMD5";
	public static final String HMACSHA1 = "HMACSHA1";
	public static final String HMACSHA256 = "HMACSHA256";
	public static final String CERTSRV = "CERTSRV";
	public static final String CERTPA = "CERTPA";
	public static final String SEPARADOR = ":";
	public static final String INFORMAR = "INFORMAR";
	public static final String INIT = "INIT";
	public static final String RTA = "RTA";
	public static final String INFO = "INFO";
	public static final String ERROR = "ERROR";
	public static final String ERROR_FORMATO = "Error en el formato. Cerrando conexion";
	public static final String ERROR_CONFIRMACION = "Error confirmando recepcion de numero cifrado. Cerrando conexion";
	public String num1;
	public String num2;
	private int cont;
	
	/**
	 * Metodo que se encarga de imprimir en consola todos los errores que se 
	 * producen durante la ejecuaci�n del protocolo. 
	 * Ayuda a controlar de forma rapida el cambio entre imprimir y no imprimir este tipo de mensaje
	 */
	private void printError(Exception e) {
//			try {
//				escritor.escribirLineaError();
//				e.printStackTrace();
//			} catch (IOException e1) {
//				e.printStackTrace();
//			}
			System.out.println(cont+","+e.getMessage()); 
	}
	/**
	 * Metodo que se encarga de leer los datos que envia el punto de atencion.
	 *  Ayuda a controlar de forma rapida el cambio entre imprimir y no imprimir este tipo de mensaje
	 */
	private static String read(BufferedReader reader) throws IOException {
		String linea = reader.readLine();
//		if(SHOW_IN)			System.out.println("<<PATN: " + linea);
		return linea;
		
	}

	/**
	 * Metodo que se encarga de escribir los datos que el servidor envia el punto de atencion.
	 *  Ayuda a controlar de forma rapida el cambio entre imprimir y no imprimir este tipo de mensaje
	 */
	private static void write(PrintWriter writer, String msg) {
		writer.println(msg);
//		if(SHOW_OUT)		System.out.println(">>SERV: " + msg);
	}
	/**
	 * Metodo que establece el protocolo de comunicacion con el punto de atencion.
	  */

	public void atenderCliente(Socket s, int pCont){
		try{
			cont=pCont;
			PrintWriter writer = new PrintWriter(s.getOutputStream(), true);
			BufferedReader reader = new BufferedReader(new InputStreamReader(s.getInputStream()));
			// ////////////////////////////////////////////////////////////////////////
			// Recibe HOLA.
			// En caso de error de formato, cierra la conexion.
			// ////////////////////////////////////////////////////////////////////////
			
			String linea = read(reader);
			
			if (!linea.equals(INFORMAR)) {
				write(writer, ERROR_FORMATO);
				throw new FontFormatException(linea);
			}
			
			// ////////////////////////////////////////////////////////////////////////
			// Envia el status del servidor
			// ////////////////////////////////////////////////////////////////////////
			write(writer, EMPEZAR);
			linea = read(reader);
			if (!(linea.contains(SEPARADOR) && linea.split(SEPARADOR)[0].equals(ALGORITMOS))) {
				write(writer, ERROR_FORMATO);
				throw new FontFormatException(linea);
			}
			// Verificar los algoritmos enviados
			String[] algoritmos = linea.split(SEPARADOR);
			// Comprueba y genera la llave simetrica para comunicarse con el
			// servidor.

			// Comprueba que el algoritmo asimetrico sea RSA.
			if (!algoritmos[1].equals(RSA)) {
				write(writer, "ERROR:Algoritmo no soportado o no reconocido: " + algoritmos[1] + ". Cerrando conexion");
				throw new NoSuchAlgorithmException();
			}
			// Comprueba que el algoritmo HMAC sea valido.
			if (!(algoritmos[2].equals(HMACMD5) || algoritmos[2].equals(HMACSHA1) || algoritmos[2]
					.equals(HMACSHA256))) {
				write(writer, "Algoritmo no soportado o no reconocido: " + algoritmos[2] + ". Cerrando conexion");
				throw new NoSuchAlgorithmException();
			}

			// Confirmando al cliente que los algoritmos son soportados.
			write(writer, RTA + SEPARADOR + OK);

			// ////////////////////////////////////////////////////////////////////////
			// Recibiendo el certificado del cliente y el num1, si no se puede recibir el certificado se envía el error
			// ////////////////////////////////////////////////////////////////////////
			long startAuth=System.nanoTime();

			linea = read(reader);
			num1=linea.split(":")[0];
			if (!linea.split(":")[1].equals(CERTPA)) {
				write(writer, ERROR_FORMATO + ":" + linea);
				throw new FontFormatException(CERTPA);
			}

			byte[] certificadoServidorBytes = new byte[520];
			s.getInputStream().read(certificadoServidorBytes);//Se recibe el certificado del punto de atencion
			X509Certificate certificadoPuntoAtencion;
			//Se trata de reconstruir el certificado a partir de la informacion recibida
			try {
				CertificateFactory creador = CertificateFactory.getInstance("X.509");
				InputStream in = new ByteArrayInputStream(certificadoServidorBytes);
				certificadoPuntoAtencion = (X509Certificate) creador.generateCertificate(in);
				write(writer, RTA + SEPARADOR + OK);
				
			} catch (Exception e) {
				write(writer, RTA + SEPARADOR + ERROR);
				write(writer, e.getMessage());
				throw new FontFormatException("Error en el certificado recibido, no se puede decodificar");
			}
			

			// ////////////////////////////////////////////////////////////////////////
			// Enviando el certificado del servidor y el num2
			// ////////////////////////////////////////////////////////////////////////
			num2=""+Math.random();//Se genera y envia el num2
			write(writer, num2+SEPARADOR+CERTSRV);
			KeyPair keyPair = Seguridad.generateRSAKeyPair();//Se generan el par de llaves del servicor
			X509Certificate certSer;//Se genera el certificado del servidor
			try {
				certSer = Seguridad.generateV3Certificate(keyPair);
				s.getOutputStream().write(certSer.getEncoded());
				s.getOutputStream().flush();
				
			} catch (Exception e) {
				//Nunca va a pasar por acá, el certificado del servidor está bien
			}	
						
			// ////////////////////////////////////////////////////////////////////////
			// Recibiendo confirmacion de recepción del certificado
			//////////////////////////////////////////////////////////////////////////
			linea = read(reader);
			if (!linea.split(":")[1].equals(OK)) {
				write(writer, ERROR_CONFIRMACION + ":" + linea);
				//throw new FontFormatException(CERTPA);
			}

			// ////////////////////////////////////////////////////////////////////////
			// Enviando numero1 cifrado
			// ////////////////////////////////////////////////////////////////////////
			write(writer, num1);

			// ////////////////////////////////////////////////////////////////////////
			// Recibiendo confirmacion de autenticación
			//////////////////////////////////////////////////////////////////////////
			linea = read(reader);
			if (!linea.split(":")[1].equals(OK)) {
				write(writer, ERROR_CONFIRMACION + ":" + linea);
				//throw new FontFormatException(CERTPA);
			}			
			
			// ////////////////////////////////////////////////////////////////////////
			// Recibe el num2 cifrado con la llave privada del punto de atencion, se verifica si corresponde a la del certificado recibido.
			// ////////////////////////////////////////////////////////////////////////
			linea = read(reader);
			//Se autentica el punto de atencion
			if(linea.equals(num2))
			{
				write(writer, RTA+SEPARADOR+OK);
			}
			else
			{
				write(writer,  RTA+SEPARADOR+ERROR);
				write(writer,  "El numero no corresponde con el enviado, cerrando conexión");
				throw new FontFormatException(linea);
			}
			long endAuth=System.nanoTime();

			
			// ////////////////////////////////////////////////////////////////////////
			// Recibe la llave simétrica cifrada con la llave publica del servidor y con la llave privada del puntoi de atencion
			// ////////////////////////////////////////////////////////////////////////
			long startAct=System.nanoTime();

			linea = read(reader);
		
			// ////////////////////////////////////////////////////////////////////////
			// Recibe las ordenes del punto de atencion
			// ////////////////////////////////////////////////////////////////////////

			linea = read(reader);

			String ordenes = linea;
			// ////////////////////////////////////////////////////////////////////////
			// Recibe el hash de las ordenes
			// ////////////////////////////////////////////////////////////////////////
			
			linea = read(reader);
			String ordenes2 = linea;
			
			
			

			// ////////////////////////////////////////////////////////////////////////
			// Verifica el hassh y termina la conexion.
			// ////////////////////////////////////////////////////////////////////////
			if(ordenes.equals(ordenes2))
			{
				write(writer, RTA + SEPARADOR +  OK);
				write(writer,"Termino requerimientos del cliente en perfectas condiciones.");
			}
			else 
			{
				write(writer, RTA + SEPARADOR +  ERROR);
				write(writer,"El resumen digital no correspone a las ordenes enviadas, el archivo se encuentra corrupto");
			}

			long endAct=System.nanoTime();
//			escritor.escribirLinea((endAuth-startAuth)+"", (endAct-startAct)+"");
			System.out.println(cont+","+(endAuth-startAuth) + "," + (endAct-startAct));		
			
		} catch (NullPointerException e) {
			// Probablemente la conexion fue interrumpida.
			printError(e);
		} catch (IOException e) {
			// Error en la conexion con el cliente.
			printError(e);
		} catch (FontFormatException e) {
			// Si hubo errores en el protocolo por parte del cliente.
			printError(e);
		} catch (NoSuchAlgorithmException e) {
			// Si los algoritmos enviados no son soportados por el servidor.
			printError(e);
		}
		 catch (IllegalStateException e) {
			// El certificado no se pudo generar.
			// No deberia alcanzarce en condiciones normales de ejecuci��n.
			printError(e);
		} // catch (CertificateNotYetValidException e) {
			// El certificado del cliente no se pudo recuperar.
			// El cliente deberia revisar la creacion y envio de su
			// certificado.
		//	printError(e);
	//	} 
	catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}  finally {
			try {
				s.close();
			} catch (Exception e) {
				// DO NOTHING
			}
		}
	}


}
