import java.io.*;
import java.util.*;
import java.security.*;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.*;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;

/**
 * Practica JCA
 * 
 * @author Gonzalo Bueno Rodriguez & Borja Alberto Tirado Galan
 *
 */

public class Main {

	// Instancia de scanner para las opciones del menu
	private Scanner opcion;
	int seleccion;
	int count;
	byte[] salt;
	String algoritmo, autenticacion;

	/**
	 * Constructor de la clase principal, aqui se definen todos los atributos por
	 * defecto
	 */
	public Main() {
		this.opcion = new Scanner(System.in);
		this.count = 1024;
		this.algoritmo = "PBEWithMD5AndDES";
		this.autenticacion = "MD2";
		this.salt = new byte[] { 0x7d, 0x60, 0x43, 0x5f, 0x02, 0x09, 0x0f, 0x0a };
	}

	public void setOpcion(Scanner opcion) {
		this.opcion = opcion;
	}

	public Scanner getOpcion() {
		return opcion;
	}

	/**
	 * Muestra los algoritmos de cifrado que se encuentran disponibles
	 */
	public void mostrarAlgoritmosCifrado() {
		System.out.println("======================================================");
		System.out.println("1 : PBEWithMD5AndDES");
		System.out.println("2 : PBEWithMD5AndTripleDES");
		System.out.println("3 : PBEWithSHA1AndDESede");
		System.out.println("4 : PBEWithSHA1AndRC2_40");
	}

	/**
	 * Metodo para la seleccion del algoritmo a utilizar
	 * 
	 * @param ninguno
	 * @return tipo String con el algoritmo seleccionado
	 */
	public void menuSeleccion() {

		// entrada por teclado del usuario
		System.out.println("Seleccione un algoritmo de cifrado: ");
		mostrarAlgoritmosCifrado();
		int entrada = opcion.nextInt();
		switch (entrada) {
		case 1:
			algoritmo = "PBEWithMD5AndDES";
			break;
		case 2:
			algoritmo = "PBEWithMD5AndTripleDES";
			break;
		case 3:
			algoritmo = "PBEWithSHA1AndDESede";
			break;
		case 4:
			algoritmo = "PBEWithSHA1AndRC2_40";
			break;
		default:
			System.out.println("ERROR en la seleccion del algoritmo de cifrado...");
			System.out.println("Opcion seleccionada: " + entrada + "\n");
			break;
		}

		menuAutenticacion();

	}

	/**
	 * Muestra por pantalla los algoritmos de autenticacion disponibles
	 */
	public void mostrarAlgoritmosAuth() {
		System.out.println("======================================================");
		System.out.println("1 : MD2");
		System.out.println("2 : MD5");
		System.out.println("3 : SHA-1");
		System.out.println("4 : SHA-256");
		System.out.println("5 : SHA-384");
	}

	/**
	 * Metodo encargado de escoger el algoritmo de autenticacion
	 */
	public void menuAutenticacion() {

		System.out.println("Seleccione un algoritmo de autenticacion: ");
		mostrarAlgoritmosAuth();
		int entrada = opcion.nextInt();
		switch (entrada) {
		case 1:
			autenticacion = "MD2";
			break;
		case 2:
			autenticacion = "MD5";
			break;
		case 3:
			autenticacion = "SHA-1";
			break;
		case 4:
			autenticacion = "SHA-256";
			break;
		case 5:
			autenticacion = "SHA-384";
			break;
		default:
			System.out.println("ERROR en la seleccion...");
			System.out.println("Opcion seleccionada: " + entrada + "\n");
			break;
		}
	}

	/**
	 * Metodo para la seleccion del algoritmo a utilizar
	 * 
	 * @param ninguno
	 * @return tipo int con la operacion seleccionada
	 */
	public void menuOpciones() {
		System.out.println("===========================================================================");
		System.out.println("Elija la operación que desea realizar con el fichero:");
		System.out.println("Nota: El fichero debe encontrarse en el mismo directorio que el principal");
		System.out.println("1. Cifrado de fichero");
		System.out.println("2. Descifrado de fichero");
		System.out.println("3. Configuracion");
		System.out.println("4. Salir");
		seleccion = opcion.nextInt();

	}

	/**
	 * Metodo para la generacion de clave de sesion
	 * 
	 * @param String con algoritmo elegido
	 * @return SecretKey para clave de sesion
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeySpecException
	 */
	public SecretKey generarClaveSesion(String algoritmoElegido)
			throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
		boolean iguales = false;
		String clave1 = "";
		String clave2 = "";

		while (!iguales) {// comprobacion de que la clave se introduce correctamente en 2 ocasiones
			System.out.println("Introduzca la clave");
			Scanner scanner = new Scanner(System.in);
			clave1 = scanner.nextLine();

			System.out.println("Vuelva a introducir la clave");
			Scanner scanner2 = new Scanner(System.in);
			clave2 = scanner2.nextLine();

			if (clave1.equals(clave2)) {
				iguales = true;
			} else {
				System.out.println("Las frases introducidas no coinciden, vuelva a intentarlo por favor");
			}
		}
		char[] claveChar = clave1.toCharArray();

		try {
			// generacion de clave de sesion con SecretKeyFactory con el algoritmo elegido
			PBEKeySpec pbeKS = new PBEKeySpec(claveChar);
			PBEParameterSpec PBEPS = new PBEParameterSpec(salt, count);
			SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(algoritmoElegido);
			SecretKey claveSecreta = keyFactory.generateSecret(pbeKS);
			return claveSecreta;
		} catch (Exception e) {
			e.printStackTrace();
		}

		return null;

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
	public void cifradoFichero(String algoritmoElegido, String archivo)
			throws NoSuchAlgorithmException, InvalidKeySpecException, IOException, NoSuchPaddingException,
			InvalidKeyException, InvalidAlgorithmParameterException {
		System.out.println("Cifrando: " + archivo + "\n");

		/*
		 * Creacion de la cabecera, indicamos el byte de operacion, el algoritmo de
		 * cifrado el algoritmo de autenticacion y el codigo salt
		 */
		Header header = new Header(Options.OP_NONE, algoritmo, autenticacion, salt);

		// Stream de entrada y salida de ficheros, el cifrado sera cifrado.cif
		FileInputStream inputStream = new FileInputStream(archivo);
		FileOutputStream outputStream = new FileOutputStream(archivo + ".cif");
		/* Guardamos la cabecera del flujo */
		header.save(outputStream);
		/* Clave de sesion */
		SecretKey claveSecreta;
		claveSecreta = generarClaveSesion(algoritmoElegido);
		PBEParameterSpec PBEPS = new PBEParameterSpec(salt, count);
		/* Creamos la instancia de la clase Cipher, encargado de cifrar */
		Cipher c = Cipher.getInstance(algoritmoElegido);
		c.init(Cipher.ENCRYPT_MODE, claveSecreta, PBEPS); // seleccion de modo cifrado
		CipherOutputStream outputStreamCifrado = new CipherOutputStream(outputStream, c);
		byte[] B = new byte[1024];

		int input = inputStream.read(B);

		while (input != -1) {
			outputStreamCifrado.write(B, 0, input);
			input = inputStream.read(B);
		}

		System.out.println("Cifrado realizado con exito... \n");
		outputStreamCifrado.flush();
		outputStreamCifrado.close();
		inputStream.close();
		outputStream.close();

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
	public final void descifradoFichero(String archivo) throws NoSuchAlgorithmException, InvalidKeySpecException,
			IOException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException {
		System.out.println("Descifrando: " + archivo + "\n");
		/* Inicializacion de flujos de lectura y escritura */
		FileOutputStream outputStream = new FileOutputStream(archivo + ".cla");
		FileInputStream inputStream = new FileInputStream(archivo);
		/* Creacion y carga de la cabecera */
		Header header = new Header();
		header.load(inputStream);
		/* Crear la clave */
		SecretKey claveSecreta = generarClaveSesion(algoritmo);
		/* Instanciamos la clase Cipher */
		Cipher c = Cipher.getInstance(algoritmo);
		PBEParameterSpec PBEPS = new PBEParameterSpec(salt, count);
		/* Seleccion de modo descifrado */
		c.init(Cipher.DECRYPT_MODE, claveSecreta, PBEPS);
		CipherInputStream ficheroCifrado = new CipherInputStream(inputStream, c);

		byte[] B = new byte[1024];
		int input = inputStream.read(B);
		while (input != -1) {
			outputStream.write(B, 0, input);
			input = inputStream.read(B);
		}
		System.out.println("Descifrado realizado con exito...\n");
		ficheroCifrado.close();
		inputStream.close();
		outputStream.flush();
		outputStream.close();

	}

	public void configuracion(int entrada) {
		int subEntrada = 1;
		switch (entrada) {
		case 1:
			while (subEntrada != 0) {
				System.out.println("Selecciona el algoritmo para descifrar");
				mostrarAlgoritmosCifrado();
				System.out.println("0. Volver al menu");
				subEntrada = opcion.nextInt();
				try {
					algoritmo = Options.cipherAlgorithms[subEntrada];
					System.out.println("Algoritmo de cifrado cambiado a " + algoritmo);
					subEntrada = 0;
				} catch (Exception e) {
					// TODO: handle exception
				}
			}

			break;
		case 2:
			while (subEntrada != 0) {
				System.out.println("Selecciona el algoritmo para autenticar");
				mostrarAlgoritmosAuth();
				System.out.println("0. Volver al menu");
				subEntrada = opcion.nextInt();
				try {
					algoritmo = Options.authenticationAlgorithms[subEntrada];
					System.out.println("Algoritmo de cifrado cambiado a " + algoritmo);
					subEntrada = 0;
				} catch (Exception e) {
					// TODO: handle exception
				}
			}
			break;
		case 3:
			mostrarAlgoritmosCifrado();
			break;
		case 4:
			mostrarAlgoritmosAuth();
			break;
		default:
			System.out.println("ERROR en la seleccion...");
			break;
		}
		System.out.println("=================================================");

	}

	public void mostrarConfig() {
		System.out.println("Seleccione el parametro que desee modificar:");
		System.out.println("1 : Algoritmo de cifrado");
		System.out.println("2 : Algoritmo de autenticacion");
		System.out.println("3 : Mostrar algoritmos de cifrado");
		System.out.println("4 : Mostrar algoritmos de autenticacion");
		System.out.println("0 : Volver al menu principal");
	}

	public static void main(final String[] args) throws IOException, InvalidKeyException, NoSuchAlgorithmException,
			InvalidKeySpecException, NoSuchPaddingException, InvalidAlgorithmParameterException {
		Main main = new Main();

		Scanner entrada = new Scanner(System.in);
		int config = 1;
		// Invocacion de menus
		while (main.seleccion != 4) {
			main.menuOpciones();
			try {
				switch (main.seleccion) {
				case 1: // Cifrar fichero
					System.out.println("Introduzca el nombre del fichero que desea cifrar con la extension");
					String archivo1 = entrada.next();
					main.menuSeleccion();
					main.cifradoFichero(main.algoritmo, archivo1);
					System.out.println("Fichero cifrado, puede encontrarlo como cifrado.cif");
					System.out.println("=======================================================\n");
					break;
				case 2: // Descifrar fichero
					System.out.println("Introduzca la ruta del fichero que desea descifrar con la extension");
					String archivo2 = entrada.next();
					main.descifradoFichero(archivo2);
					System.out.println(
							"Fichero descifrado, puede encontrarlo como descifrado.cla, si desea revisarlo puede cambiar la extension a .cla ");
					System.out.println("=======================================================\n");
					break;
				case 3: // Configuracion
					while (config != 0) {
						try {
							main.mostrarConfig();
							config = entrada.nextInt();
							if (config != 0)
								main.configuracion(config);

						} catch (Exception e) {
							// TODO: handle exception
						}

					}
					break;

				case 4: // salir del programa
					break;

				default:
					System.out.println("Opcion incorrecta, vuelva a introducir otro valor (1-4)\n");
					break;
				}
			} catch (Exception e) {
				e.printStackTrace();
			}

		}
		System.out.println("Exit...");
		entrada.close();
	}
}