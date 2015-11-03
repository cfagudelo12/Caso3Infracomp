package puntoAtencion;


import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.Security;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Date;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.security.auth.x500.X500Principal;

import org.apache.commons.lang.ArrayUtils;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.x509.X509V3CertificateGenerator;

@SuppressWarnings("deprecation")
public class PuntoAtencionSinSeguridad {

	/**
	 * Constantes de protocolo
	 */
	private final static String INFORMAR = "INFORMAR";
	private final static String EMPEZAR = "EMPEZAR";
	private final static String ALGORITMOS = "ALGORITMOS";
	private final static String RTA = "RTA";
	private final static String OK = "OK";
	private final static String CERTPA = "CERTPA";
	private final static String CERTSRV = "CERTSRV";
	private final static String ERROR = "ERROR";
	private final static String INIT = "INIT";

	/**
	 * Constantes de algoritmos
	 */
	public final static String RSA = "RSA";
	public final static String HMACMD5 = "HMACMD5";
	public final static String HMACSHA1 = "HMACSHA1";
	public final static String HMACSHA256 = "HMACSHA256";

	/**
	 * Atributos
	 */
	private Socket canal;
	private PrintWriter out;
	private BufferedReader in;
	private String host;
	private int port;
	private String algoritmoHMAC;
	private KeyPair keyPair;
	private PublicKey publicKeyServidor;
	private double num1;
	private double num2;
	private int numeroOrdenes;

	public PuntoAtencionSinSeguridad(String host, int port, String algoritmoHMAC, int numeroOrdenes) {
		this.host=host;
		this.port=port;
		this.algoritmoHMAC=algoritmoHMAC;
		this.numeroOrdenes=numeroOrdenes;
		try {
			KeyPairGenerator generator = KeyPairGenerator.getInstance(RSA);
			generator.initialize(1024);
			keyPair = generator.generateKeyPair();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
	}

	private void conectar() throws Exception {
		canal = new Socket(host, port);
		out = new PrintWriter(canal.getOutputStream(), true);
		in = new BufferedReader(new InputStreamReader(canal.getInputStream()));
	}

	public void procesar() throws Exception {
		//---------------------------------------
		//Configuración
		//---------------------------------------
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
		conectar();
		
		//---------------------------------------
		//Etapa 1
		//---------------------------------------
		String linea = "";
		out.println(INFORMAR);
		linea = in.readLine();
		if(!linea.equals(EMPEZAR)){
			throw new Exception("Error en el protocolo. Se esperaba: "+EMPEZAR+ ". Se recibio: "+linea);
		}
		out.println(ALGORITMOS+":"+RSA+":"+algoritmoHMAC);
		linea = in.readLine();
		String[] rta = linea.split(":");
		if(rta[1].equals(ERROR)||!rta[1].equals(OK)) {
			throw new Exception("Se produjo un error. Se esperaba: "+OK+ " Se recibio: "+linea);
		}

		//---------------------------------------
		//Etapa 2
		//---------------------------------------
		num1=Math.random()*1000;
		out.println(num1+":"+CERTPA);
		canal.getOutputStream().write(generarCertificado().getEncoded());
		canal.getOutputStream().flush();
		linea = in.readLine();
		rta = linea.split(":");
		if(rta[1].equals(ERROR)||!rta[1].equals(OK)) {
			throw new Exception("Se produjo un error. Se esperaba: "+OK+ ". Se recibio: "+linea);
		}
		linea = in.readLine();
		rta = linea.split(":");
		num2= Double.parseDouble(rta[0]);
		if(!rta[1].equals(CERTSRV)) {
			throw new Exception("Se produjo un error. Se esperaba: "+CERTSRV+ ". Se recibio: "+linea);
		}
		try{
			CertificateFactory factory=CertificateFactory.getInstance("X.509");
			java.security.cert.Certificate certificadoServidor=factory.generateCertificate(canal.getInputStream());
			publicKeyServidor=certificadoServidor.getPublicKey();
			out.println(RTA+":"+OK);
		} catch(Exception e) {
			out.println(RTA+":"+ERROR);
			throw new Exception("Se produjo un error.");
		}

		//---------------------------------------
		//Etapa 3
		//---------------------------------------
		
		String numero1= in.readLine();

		if(num1!=Double.parseDouble(numero1)) {
			out.println(RTA+":"+ERROR);
			throw new Exception("Se produjo un error. Se esperaba: "+num1+ ". Se recibio: "+numero1);
		}
		out.println(RTA+":"+OK);

		String envio= num2+"";
		out.println(envio);
		linea = in.readLine();
		rta = linea.split(":");
		if(rta[1].equals(ERROR)||!rta[1].equals(OK)) {
			throw new Exception("Se produjo un error. Se esperaba: "+OK+ ". Se recibio: "+linea);
		}

		//---------------------------------------
		//Etapa 4
		//---------------------------------------
		
		out.println(numeroOrdenes);
		
		out.println(numeroOrdenes);
		
		out.println(numeroOrdenes);
		
		//Se espera por el resultado final
		linea = in.readLine();
		rta = linea.split(":");
		if(rta[1].equals(ERROR)||!rta[1].equals(OK)) {
			throw new Exception("Se produjo un error. Se esperaba: "+OK+ " Se recibio: "+linea);
		}
	}

	public X509Certificate generarCertificado() throws CertificateEncodingException, InvalidKeyException, IllegalStateException, NoSuchProviderException, NoSuchAlgorithmException, SignatureException {
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
		X509V3CertificateGenerator certGen = new X509V3CertificateGenerator();
		certGen.setSerialNumber(BigInteger.valueOf(System.currentTimeMillis()));
		certGen.setIssuerDN(new X500Principal("CN=Test Certificate"));
		certGen.setNotBefore(new Date(System.currentTimeMillis() - 50000));
		certGen.setNotAfter(new Date(System.currentTimeMillis() + 50000));
		certGen.setSubjectDN(new X500Principal("CN=Test Certificate"));
		certGen.setPublicKey(keyPair.getPublic());
		certGen.setSignatureAlgorithm("SHA256WithRSAEncryption");
		certGen.addExtension(X509Extensions.BasicConstraints, true, new BasicConstraints(false));
		certGen.addExtension(X509Extensions.KeyUsage, true, new KeyUsage(KeyUsage.digitalSignature|KeyUsage.keyEncipherment));
		certGen.addExtension(X509Extensions.ExtendedKeyUsage, true, new ExtendedKeyUsage(KeyPurposeId.id_kp_serverAuth));
		certGen.addExtension(X509Extensions.SubjectAlternativeName, false, new GeneralNames(new GeneralName(GeneralName.rfc822Name, "test@test.test")));
		return certGen.generateX509Certificate(keyPair.getPrivate(), "BC");
	}

	public static void main(String[] args) {
		PuntoAtencionSinSeguridad puntoAtencion = new PuntoAtencionSinSeguridad("localhost", 443, HMACSHA256, 4);
		try {
			puntoAtencion.procesar();
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
}