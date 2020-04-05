
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.SecretKey;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;
import javax.crypto.SecretKeyFactory;

/**
 * Practica JCA
 * 
 * @author Gonzalo Bueno Rodriguez & Borja Alberto Tirado Galan
 *
 */

//Clase SecureRandom para generar salt de manera aleatoria
import java.security.SecureRandom;

/*Clase encargada del cifrado y descifrado de ficheros*/
public class Cifrar {
	/* Atributos */

	/* Salt: conjunto de datos aleatorios para incluir en la cabecera */
	private byte[] salt;
	/* Numero de iteraciones aplicadas a los algoritmos hash */
	private int count;

	/* Constructor por defecto de Cifrar */
	public Cifrar() {
		this.salt = new byte[] { 0x0 };
		this.count = 1024;
	}

	/**
	 * Generador de datos aleatorios
	 * 
	 * @param size tamano de la estructura
	 * @return estructura de datos aleatorios tipo byte []
	 */
	public static byte[] generateRandomSalt(int size) {
		if (size < 6 || size > 1024) {
			size = 6;
		}
		byte[] salt = new byte[size];
		SecureRandom random = new SecureRandom();
		random.nextBytes(salt);
		return salt;
	}

	/**
	 * Clase encargarda de generar las claves
	 * 
	 * @param algorithm algoritmo de cifrado a utilizar
	 * @param passwd    contrasena de paso
	 * @return devuelve una clave tipo SecretKey
	 */
	private SecretKey generarClaves(String algorithm, char[] passwd) {
		Boolean generada = false;
		SecretKey skeygenerada = null;
		try {
			if (!generada) {
				PBEKeySpec pbeKeySpec = new PBEKeySpec(passwd);
				SecretKeyFactory kf = SecretKeyFactory.getInstance(algorithm);
				SecretKey skey = kf.generateSecret(pbeKeySpec);
				skeygenerada = skey;
				generada = true;
				return skey;
			} else {
				return skeygenerada;
			}
		} catch (Exception localException) {
			localException.printStackTrace();
		}
		return null;
	}

	/**
	 * Clase encargada de realizar el proceso de cifrado
	 * 
	 * @param file      ruta del fichero
	 * @param passwd    clave de paso
	 * @param algorithm algoritmo de cifrado
	 * @return True: cifrado satisfactorio. False: error en el cifrado
	 */
	public Boolean cifrar(String file, char[] passwd, String alg1, String alg2) {
		Boolean cifrado = false;
		System.out.println("Proceso de cifrado de <" + file + "> con Algoritmo: " + alg1 + "\n");
		try {
			/* Flujo de entrada y salida */
			FileInputStream fis = new FileInputStream(file);
			FileOutputStream fos = new FileOutputStream(file + ".cif");

			/* Creacion de instancia Header */
			this.salt = generateRandomSalt(8);
			Header header = new Header(Options.OP_SYMMETRIC_CIPHER, alg1, alg2, this.salt);
			/* Generacion de la clave */
			SecretKey secretKey = generarClaves(alg1, passwd);
			/* Escritura de la cabecera del fichero */
			header.save(fos);
			/* Comprobacion del guardado de la cabecera*/
			if (!testHeader(header, alg1, alg2, this.salt))
				System.out.println("Error en el guardado de la cabecera");

			/* Creacion del Cipher */
			Cipher cipher = Cipher.getInstance(alg1);

			/* Obtenemos los parametros PBE */
			PBEParameterSpec pPS = new PBEParameterSpec(salt, this.count);
			cipher.init(Cipher.ENCRYPT_MODE, secretKey, pPS);
			CipherOutputStream cos = new CipherOutputStream(fos, cipher);

			int i, j = 0;
			byte[] array = new byte[1024];
			/*
			 * Nos permitirán cifrar/descifrar un flujo de datos con el Cipher anterior. Una
			 * vez preparado, podremos leer o escribir en el flujo y al mismo tiempo se iran
			 * cifrando o descifrando los datos
			 */

			while ((i = fis.read(array)) != -1) {
				cos.write(array, 0, i);
				j += i;
				System.out.print(i + ".");
			}

			System.out.println("\nCifrado: " + j + "\n");
			/* Cierre de flujos */
			cos.flush();
			cos.close();

			fos.close();
			fis.close();
			cifrado = true;
		} catch (FileNotFoundException FileNotFoundException) {
			System.out.println("Fichero no encontrado: " + file + "\n");
		} catch (IOException IOException) {
			System.out.println("Error de E/S \n");
		} catch (Exception localException) {
			System.out.println(localException.getMessage() + "\n");
		}
		return cifrado;
	}
	/**
	 * Metodo que comprueba los datos de la cabecera
	 * @param header Instancia cabecera
	 * @param alg1 Algoritmo de cifrado
	 * @param alg2 Algoritmo de comprobacion
	 * @param salt2 Salt
	 * @return Devuelve verdadero si todos los datos coinciden, falso en caso contrario
	 */
	private Boolean testHeader(Header header, String alg1, String alg2, byte[] salt2) {
		if (alg1 == header.getAlgorithm1() && alg2 == header.getAlgorithm2() && salt2 == header.getData())
			return true;

		return false;
	}

	/**
	 * Clase encargada de realizar el proceso de descifrado
	 * 
	 * @param file      ruta del fichero
	 * @param passwd    clave de paso
	 * @param algorithm algoritmo de descifrado
	 * @return True: descifrado satisfactorio. False: error en el descifrado
	 */
	public final Boolean descifrar(String file, char[] passwd, String alg1, String alg2) {
		Boolean descifrado = false;
		try {
			System.out.println("Proceso de descifrado de <" + file + ">\n");
			/* Flujos de lectura y escritura */
			FileInputStream fis = new FileInputStream(file);
			FileOutputStream fos = new FileOutputStream(file + ".cla");

			/* Obtencion de la clave */
			SecretKey secretKey = generarClaves(alg1, passwd);
			/* Creacion de instancia Header */
			Header header = new Header();
			/* Lectura de la cabecera del fichero */
			header.load(fis);
			/* Comprobacion de la carga de la cabecera*/
			if (!testHeader(header, alg1, alg2, this.salt))
				System.out.println("Error en la carga de la cabecera");
			
			/* getInstance de Cipher */
			Cipher cipher = Cipher.getInstance(alg1);
			PBEParameterSpec pPS = new PBEParameterSpec(header.getData(), this.count);
			cipher.init(Cipher.DECRYPT_MODE, secretKey, pPS);

			CipherInputStream cis = new CipherInputStream(fis, cipher);

			byte[] array = new byte[1024];
			int i, j = 0;
			/* Escritura del fichero de los bloques obtenidos */
			while ((i = cis.read(array)) > 0) {
				fos.write(array, 0, i);
				j += i;
				System.out.print(i + ".");
			}
			System.out.println("\nDescifrado: " + j + "\n");
			/* Cierre de flujos */
			cis.close();
			fis.close();
			fos.close();
			descifrado = true;
		} catch (IOException localIOException) {
			System.out.println("\n[x] Proceso de descifrado incompleto: ");
			System.out.println("\n[x] 	Error de E/S.");
			System.out.println("\n[x] 	Comprueba que la ruta y credenciales son correctos\n");
		} catch (Exception localException) {
			System.out.println(localException.getMessage() + "\n");
			localException.printStackTrace();
		}
		return descifrado;
	}
}
