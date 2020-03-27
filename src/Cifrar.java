
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.SecretKey;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;
import javax.crypto.SecretKeyFactory;

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
		this.salt = generateRandomSalt(8);
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
	public Boolean cifrar(String file, char[] passwd, String algorithm) {
		Boolean cifrado = false;
		System.out.println("Proceso de cifrado de <" + file + "> con Algoritmo: " + algorithm + "\n");
		try {
			/* Flujo de entrada y salida */
			FileInputStream fileIn = new FileInputStream(file);
			FileOutputStream fileOut = new FileOutputStream(file + ".cif");
			/* Creacion de instancia Header */
			Header header = new Header(algorithm, this.salt);

			/* Creacion del Cipher */
			Cipher cipher = Cipher.getInstance(algorithm);

			/* Generacion de la clave */
			SecretKey secretKey = generarClaves(algorithm, passwd);
			/* Obtenemos los parametros PBE */
			PBEParameterSpec pPS = new PBEParameterSpec(salt, this.count);
			cipher.init(Cipher.ENCRYPT_MODE, secretKey, pPS);
			CipherInputStream cis = new CipherInputStream(fileIn, cipher);
			int i = 0;
			byte[] array = new byte[1024];
			/*
			 * Nos permitirán cifrar/descifrar un flujo de datos con el Cipher anterior. Una
			 * vez preparado, podremos leer o escribir en el flujo y al mismo tiempo se iran
			 * cifrando o descifrando los datos
			 */

			/* Escritura de la cabecera del fichero */
			header.save(fileOut);

			while ((i = cis.read(array)) != -1) {
				fileOut.write(array, 0, i);
			}

			/* Cierre de flujos */
			cis.close();

			fileOut.close();
			fileOut.flush();
			fileIn.close();
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
	 * Clase encargada de realizar el proceso de descifrado
	 * 
	 * @param file      ruta del fichero
	 * @param passwd    clave de paso
	 * @param algorithm algoritmo de descifrado
	 * @return True: descifrado satisfactorio. False: error en el descifrado
	 */
	public final Boolean descifrar(String file, char[] passwd, String algorithm) {
		Boolean descifrado = false;
		try {
			System.out.println("Proceso de descifrado de <" + file + ">\n");
			/* Flujos de lectura y escritura */
			FileInputStream fileIn = new FileInputStream(file);
			FileOutputStream ficherOut = new FileOutputStream(file + ".cla");

			/* Creacion de instancia Header */
			Header header = new Header();

			/* Lectura de la cabecera del fichero */
			header.load(fileIn);
			algorithm = header.getAlgorithm1();
			salt = header.getData();

			/* getInstance de Cipher */
			Cipher cipher = Cipher.getInstance(header.getAlgorithm1());

			/* Obtencion de la clave */
			SecretKey secretKey = generarClaves(header.getAlgorithm1(), passwd);
			/* Parametros PBE */

			PBEParameterSpec pPS = new PBEParameterSpec(header.getData(), this.count);
			cipher.init(Cipher.DECRYPT_MODE, secretKey, pPS);
			CipherOutputStream cos = new CipherOutputStream(ficherOut, cipher);

			byte[] array = new byte[1024];
			int i;
			/* Escritura del fichero de los bloques obtenidos */
			while ((i = fileIn.read(array)) > 0) {
				cos.write(array, 0, i);
			}

			/* Cierre de flujos */
			cos.close();
			fileIn.close();
			ficherOut.flush();
			ficherOut.close();
			descifrado = true;
		} catch (IOException localIOException) {
			System.out.println("Proceso de descifrado incompleto");
			System.out.println("Error de E/S.");
			System.out.println("Comprueba que las ruta y credenciales son correctos\n");
		} catch (Exception localException) {
			System.out.println(localException.getMessage() + "\n");
			localException.printStackTrace();
		}
		return descifrado;
	}
}
