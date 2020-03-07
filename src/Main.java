import java.io.*;
import java.util.*;
import java.security.*;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.*;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;
/**
 * Practica JCA
 * @author Gonzalo Bueno Rodríguez & Borja Alberto Tirado Galan
 *
 */


public class Main {

	static Scanner opcion = new Scanner(System.in);// instancia de scanner para las opciones del menu
	static int count = 1024;
	static byte[] SALT = new byte[] { 0x7d, 0x60, 0x43, 0x5f, 0x02, 0x09, 0x0f, 0x0a };
	
	
	public void setOpcion(final Scanner opcion) {
		Main.opcion = opcion;
	}

	public Scanner getOpcion() {
		return opcion;
	}

	/**
	 * Metodo para la seleccion del algoritmo a utilizar
	 * 
	 * @param ninguno
	 * @return tipo String con el algoritmo seleccionado
	 */
	public static String menuSeleccion() {
		String algoritmo = "";
		System.out.println("Seleccione el algoritmo con el que quiere encriptar:");
		System.out.println("1 : PBEWithMD5AndDES");
		System.out.println("2 : PBEWithMD5AndTripleDES");
		System.out.println("3 : PBEWithSHA1AndDESede");
		System.out.println("4 : PBEWithSHA1AndRC2_40");

		final int entrada = opcion.nextInt();// entrada por teclado del usuario
		switch (entrada) {
		case 1:
			return algoritmo = "PBEWithMD5AndDES";
		case 2:
			return algoritmo = "PBEWithMD5AndTripleDES";
		case 3:
			return algoritmo = "PBEWithSHA1AndDESede";
		case 4:
			return algoritmo = "PBEWithSHA1AndRC2_40";
		default:
			System.out.println("ERROR");
			return algoritmo;
		}
	}

	/**
	 * Metodo para la seleccion del algoritmo a utilizar
	 * 
	 * @param ninguno
	 * @return tipo int con la operacion seleccionada
	 */
	public static int menuOpciones() {
		int seleccion = 0;
		System.out.println("Elija la operación que desea realizar con el fichero:");
		System.out.println("Nota: El fichero debe encontrarse en el mismo directorio que el principal");
		System.out.println("1. Cifrado de fichero");
		System.out.println("2. Descifrado de fichero");
		System.out.println("3. Cifrado de mensajes");
		System.out.println("4. Salir");
		seleccion = opcion.nextInt();
		return seleccion;
	}

	/**
	 * Metodo para la generacion de clave de sesion
	 * 
	 * @param String con algoritmo elegido
	 * @return SecretKey para clave de sesion
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeySpecException
	 */
	public static SecretKey generarClaveSesion(final String algoritmoElegido)
			throws IOException, NoSuchAlgorithmException, InvalidKeySpecException 
	{
		boolean iguales = false;
		String clave1 = "";
		String clave2 = "";

		while (!iguales) {// comprobacion de que la clave se introduce correctamente en 2 ocasiones
			System.out.println("Introduzca la clave");
			final Scanner scanner = new Scanner(System.in);
			clave1 = scanner.nextLine();

			System.out.println("Vuelva a introducir la clave");
			final Scanner scanner2 = new Scanner(System.in);
			clave2 = scanner2.nextLine();
		
			
			if (clave1.equals(clave2)) {
				iguales = true;
			} else {
				System.out.println("Las frases introducidas no coinciden, vuelva a intentarlo por favor");
			}
		}
		final char[] claveChar = clave1.toCharArray();// generacion de clave de sesion con SecretKeyFactory con el algoritmo
												// elegido
		final PBEKeySpec pbeKS = new PBEKeySpec(claveChar);
		final SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(algoritmoElegido);
		final SecretKey claveSecreta = keyFactory.generateSecret(pbeKS);
		
		
		return claveSecreta;

	}

	/**
	 * Metodo para el cifrado de un fichero, el fichero de salida tendrá como nombre
	 * cifrado.cif
	 * 
	 * @param String con algoritmo elegido
	 * @param String con el nombre del archivo y su extension, debe estar en el
	 *               mismo directorio
	 * @return nada
	 * @throws IOException
	 * @throws InvalidKeySpecException
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchPaddingException
	 * @throws InvalidAlgorithmParameterException
	 * @throws InvalidKeyException
	 */
	public static void cifradoFichero(final String algoritmoElegido, final String archivo, final byte[] SALT)
			throws NoSuchAlgorithmException, InvalidKeySpecException, IOException, NoSuchPaddingException,
			InvalidKeyException, InvalidAlgorithmParameterException 
	{
		final Header header = new Header();
		// stream de entrada y salida de ficheros, el cifrado sera cifrado.cif
		final FileOutputStream outputStream = new FileOutputStream("cifrado.cif");
		final FileInputStream inputStream = new FileInputStream(archivo);

		SecretKey claveSecreta;// clave de sesion
		claveSecreta = generarClaveSesion(algoritmoElegido);
		final PBEParameterSpec PBEPS = new PBEParameterSpec(SALT, count);

		final Cipher c = Cipher.getInstance(algoritmoElegido);
		c.init(Cipher.ENCRYPT_MODE, claveSecreta, PBEPS); // seleccion de modo cifrado
		final CipherOutputStream outputStreamCifrado = new CipherOutputStream(outputStream, c);
		final byte[] B = new byte[8];
		header.save(outputStream);

		int input = inputStream.read(B);

		while (input != -1) {
			outputStreamCifrado.write(B, 0, input);
			input = inputStream.read(B);
		}
		
		
	}

	/**
	 * Metodo para el cifrado de un fichero, debe estar en el mismo directorio y
	 * generara el fichero descifrado.cla mas tarde se puede editar la extension del
	 * archivo a .txt para inspeccionarlo con un editor de texto
	 * 
	 * @param String con el nombre del archivo y su extension, debe estar en el
	 *               mismo directorio
	 * @return nada
	 * @throws IOException
	 * @throws InvalidKeySpecException
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchPaddingException
	 * @throws InvalidAlgorithmParameterException
	 * @throws InvalidKeyException
	 */
	public static void descifradoFichero(final String archivo) throws NoSuchAlgorithmException, InvalidKeySpecException,
			IOException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException {
		final FileOutputStream outputStream = new FileOutputStream("descifrado.cla");
		final FileInputStream inputStream = new FileInputStream(archivo);
		final Header header = new Header();

		final SecretKey claveSecreta = generarClaveSesion(header.getAlgorithm1());
		header.load(inputStream);
		final PBEParameterSpec PBEPS = new PBEParameterSpec(SALT, count);

		final Cipher c = Cipher.getInstance(header.getAlgorithm1());
		c.init(Cipher.ENCRYPT_MODE, claveSecreta, PBEPS);
		final CipherOutputStream outputStreamCifrado = new CipherOutputStream(outputStream, c);

		final byte[] B = new byte[8];
		int input = inputStream.read(B);
		while (input != -1) {
			outputStreamCifrado.write(B, 0, input);
			input = inputStream.read(B);
		}
		outputStreamCifrado.close();
		outputStream.flush();
		outputStream.close();
		inputStream.close();

	}

	public static void cifradoFlujo() {
		
	}

	public static void main(final String[] args) throws IOException, InvalidKeyException, NoSuchAlgorithmException,
			InvalidKeySpecException, NoSuchPaddingException, InvalidAlgorithmParameterException 
	{
		final byte[] SALT = new byte[] { 0x7d, 0x60, 0x43, 0x5f, 0x02, (byte) 0xe9, (byte) 0xe0, (byte) 0xae };// salt

		// invocacion de menus
		final Scanner entrada = new Scanner(System.in);

		int seleccion = menuOpciones();
		while(seleccion != 4) 
		{
			switch (seleccion) 
			{
			case 1: //Cifrar fichero
				System.out.println("Introduzca el nombre del fichero que desea cifrar con la extension");
				final String archivo1 = entrada.next();
				final String algoritmo = menuSeleccion();
				cifradoFichero(algoritmo, archivo1, SALT);
				System.out.println("Fichero cifrado, puede encontrarlo como cifrado.cif");
				System.out.println("=======================================================");
				seleccion = menuOpciones();
				break;
			case 2: //Descifrar fichero
				System.out.println("Introduzca el nombre del fichero que desea descifrar con la extension");
				final String archivo2 = entrada.next();
				descifradoFichero(archivo2);
				System.out.println(
						"Fichero descifrado, puede encontrarlo como descifrado.cla, si desea revisarlo puede cambiar la extension a .cla ");
				System.out.println("=======================================================");
				seleccion = menuOpciones();
				break;
			case 3: //Cifrado de flujo
				
				break;
				
			case 4: //salir del programa
				System.out.println("Exit...");
				break;
				
			default:
				System.out.println("Opcion incorrecta, vuelva a introducir otro valor");
				break;
			}
		}
		
//		entrada.close();
	}
}