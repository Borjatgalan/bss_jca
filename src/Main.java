
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.*;

/**
 * Practica JCA
 * 
 * @author Gonzalo Bueno Rodriguez & Borja Alberto Tirado Galan
 *
 */

public class Main {

	// Instancia de scanner para las opciones del menu
	private Scanner opcion;
	private Cifrar cf;

	/**
	 * Constructor de la clase principal, aqui se definen todos los atributos por
	 * defecto
	 */
	public Main() {
		this.opcion = new Scanner(System.in);
		this.cf = new Cifrar();
	}

	@SuppressWarnings("null")
	public void cifrarFichero() {
		String file = null, passwd, algorithm = null;
		Boolean enc = false;
		BufferedReader br = new BufferedReader(new InputStreamReader(System.in));
		try {
			System.out.println("Introduzca la ruta del fichero que desea cifrar con la extension");
			System.out.print("Fichero: ");
			while (!enc) {
				file = br.readLine();
				if (Files.exists(Paths.get(file))) {
					enc = true;
				} else {
					System.err.println("¡ERROR! fichero no encontrado");
					System.out.println("Introduzca la ruta de nuevo");
				}
			}

			System.out.println("Introduzca su clave de paso: ");
			System.out.print("Clave: ");
			passwd = br.readLine();

			algorithm = menuAlgoritmo();
			if (cf.cifrar(file, passwd.toCharArray(), algorithm)) {
				System.out.println(
						"Cifrado completado satisfactoriamente. Pulsa cualquier tecla para regresar al menú principal");
				System.out.print("> ");
				br.readLine();
			}
			System.out.println("Fichero cifrado, puede encontrarlo como cifrado.cif");
			System.out.println("=======================================================\n");

			br.close();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	public void descifrarFichero() {
		String file, passwd = "";
		String algorithm = "";
		BufferedReader br = new BufferedReader(new InputStreamReader(System.in));
		System.out.println("Introduzca la ruta del fichero que desea descifrar con la extension");
		try {
			file = br.readLine();
			cf.descifrar(file, passwd.toCharArray(), algorithm);
			System.out.println(
					"Fichero descifrado, puede encontrarlo como descifrado.cla, si desea revisarlo puede cambiar la extension a .cla ");
			System.out.println("=======================================================\n");

		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	public void procesoPrincipal() {
		Scanner sc = new Scanner(System.in);
		Integer seleccion = 1;
		while (seleccion != 0) {
			menuOpciones();
			try {
				seleccion = sc.nextInt();
				switch (seleccion) {
				case 0:
					break;
				case 1: // Cifrar fichero
					cifrarFichero();
					break;
				case 2: // Descifrar fichero
					descifrarFichero();
					break;

				default:
					System.out.println("Opcion incorrecta, vuelva a introducir otro valor (1-3)\n");
					System.out.print(">");
					break;
				}
			} catch (Exception e) {
				e.printStackTrace();
			}

		}
		System.out.println("...Fin del programa...");
	}

	/**
	 * Metodo que muestra las opciones disponibles del programa
	 */
	public void menuOpciones() {
		System.out.println("===========================================================================");
		System.out.println("Elija la operacion que desea realizar con el fichero:");
		System.out.println("Nota: El fichero debe encontrarse en el mismo directorio que el principal");
		System.out.println("1. Cifrado de fichero");
		System.out.println("2. Descifrado de fichero");
		System.out.println("0. Salir");
		System.out.print("> ");

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
	 * 
	 */
	public String menuAlgoritmo() {
		String alg = "";
		// entrada por teclado del usuario
		System.out.println("Seleccione un algoritmo de cifrado: ");
		mostrarAlgoritmosCifrado();
		System.out.print("> ");
		int entrada = opcion.nextInt();
		switch (entrada) {
		case 1:
			alg = Options.symmetricalAlgorithms[entrada];
			break;
		case 2:
			alg = Options.symmetricalAlgorithms[entrada];
			break;
		case 3:
			alg = Options.symmetricalAlgorithms[entrada];
			break;
		case 4:
			alg = Options.symmetricalAlgorithms[entrada];
			break;
		default:
			System.out.println("ERROR en la seleccion del algoritmo de cifrado...");
			System.out.println("Opcion seleccionada: " + entrada + "\n");
			break;
		}
		System.out.println("Algoritmo seleccionado: " + Options.symmetricalAlgorithms[entrada]);

		return alg;
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
	public String menuAutenticacion() {
		String auth = "";
		System.out.println("Seleccione un algoritmo de autenticacion: ");
		mostrarAlgoritmosAuth();
		System.out.print("> ");
		int entrada = opcion.nextInt();
		switch (entrada) {
		case 1:
			auth = Options.authenticationAlgorithms[entrada];
			break;
		case 2:
			auth = Options.authenticationAlgorithms[entrada];
			break;
		case 3:
			auth = Options.authenticationAlgorithms[entrada];
			break;
		case 4:
			auth = Options.authenticationAlgorithms[entrada];
			break;
		case 5:
			auth = Options.authenticationAlgorithms[entrada];
			break;
		default:
			System.out.println("ERROR en la seleccion...");
			System.out.println("Opcion seleccionada: " + entrada + "\n");
			break;
		}
		System.out.println("Algoritmo de autenticacion seleccionado: " + Options.authenticationAlgorithms[entrada]);

		return auth;
	}

	public static void main(final String[] args) {
		Main main = new Main();
		main.procesoPrincipal();
	}
}