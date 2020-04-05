
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
	private String passwd;

	/**
	 * Constructor de la clase principal, aqui se definen todos los atributos por
	 * defecto
	 */
	public Main() {
		this.opcion = new Scanner(System.in);
		this.cf = new Cifrar();
		this.passwd = "";
	}

	/**
	 * Método que llama al cifrado por bloques con las entradas necesarias, también
	 * selecciona el algoritmo de cifrado/descifrado y pide al usuario por pantalla
	 * la frase de paso comprobando que se ha introducido 2 veces correctamente Una
	 * vez cifrado mostrará un mensaje de confirmación al usuario
	 * 
	 * @return 0
	 */
	@SuppressWarnings("null")
	public void cifrarFichero() {
		String file = null, alg1 = null,alg2 = null, passwd2 = "";
		Boolean enc = false;
		Boolean equals = false;
		BufferedReader br = new BufferedReader(new InputStreamReader(System.in));
		try {
			System.out.println("Introduzca el nombre del fichero que desea cifrar con la extension");
			System.out.print("Fichero: ");
			while (!enc) {
				file = br.readLine();
				if (Files.exists(Paths.get(file))) {
					enc = true;
				} else {
					System.err.println("ERROR! fichero no encontrado");
					System.out.println("Introduzca la ruta de nuevo");
				}
			}

			while (!equals) {
				System.out.println("Introduzca su clave de paso: ");
				passwd = br.readLine();
				System.out.println("Vuelva a introducir la clave de paso: ");
				passwd2 = br.readLine();
				if (passwd.equals(passwd2)) {
					equals = true;
				} else {
					equals = false;
					System.out.println("Las claves no coinciden, vuelva a intentarlo");

				}
			}

			alg1 = menuAlgoritmo();
			alg2 = Options.authenticationAlgorithms[0];
			if (cf.cifrar(file, passwd.toCharArray(), alg1 , alg2)) {
				System.out.println("-- Cifrado completado satisfactoriamente.\n"
						+ "Puede encontrarlo como " + file
						+ ".cif Pulsa cualquier tecla para regresar al menu principal");
			}
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	/**
	 * Metodo que llama al descifrado pidiendo al usuario por pantalla el nombre del
	 * fichero a descifrar Una vez descifrado mostrará al usuario por pantalla una
	 * confirmación
	 * 
	 * @return 0
	 */
	public void descifrarFichero() {
		String file = "", pwd = "";
		String alg1 = "", alg2 = "";
		BufferedReader br = new BufferedReader(new InputStreamReader(System.in));
		System.out.println("Introduzca el nombre del fichero que desea descifrar con la extension");
		try {
			file = br.readLine();
			System.out.println("Introduzca la frase de paso");
			pwd = br.readLine();
			
			alg1 = menuAlgoritmo();
			alg2 = Options.authenticationAlgorithms[0];
			if (cf.descifrar(file, pwd.toCharArray(), alg1, alg2)) {
				System.out.println("-- Fichero descifrado satisfactoriamente.\n"
						+ "Puede encontrarlo como " + file
						+ ".cla, si desea revisarlo puede cambiar la extension a .txt ");
			}
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	/**
	 * Metodo para el menú de opciones 0: salir 1: cifrar 2: descifrar seguirá
	 * pidiendo opciones hasta que el usuario elija 0
	 * 
	 * @return 0
	 */
	public void procesoPrincipal() throws IOException {
		boolean esc = false;
		int seleccion;
		while (!esc) {
			try {
				seleccion = menuOpciones();
				switch (seleccion) {
				case 0: // salir
					esc = true;
					break;
				case 1: // Cifrar fichero
					cifrarFichero();
					break;
				case 2: // Descifrar fichero
					descifrarFichero();
					break;

				default:
					System.out.println("Opcion incorrecta, vuelva a introducir otro valor (0-2)\n");
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
	 * 
	 * @return int op, opción elegida para el menú.
	 */
	public int menuOpciones() throws IOException {
		int op;
		System.out.println("===========================================================================");
		System.out.println("Elija la operacion que desea realizar con el fichero:");
		System.out.println("Nota: El fichero debe encontrarse en el mismo directorio que el principal");
		System.out.println("1. Cifrado de fichero");
		System.out.println("2. Descifrado de fichero");
		System.out.println("0. Salir");
		op = opcion.nextInt();

		return op;

	}

	/**
	 * Setter de opcion
	 * 
	 * @param Scanner opcion
	 * @return 0
	 */
	public void setOpcion(Scanner opcion) {
		this.opcion = opcion;
	}

	/**
	 * Getter de opción
	 * 
	 * @return Scanner opcion
	 */
	public Scanner getOpcion() {
		return opcion;
	}

	/**
	 * Muestra los algoritmos de cifrado que se encuentran disponibles
	 * 
	 * @return 0
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
	 * @return String con el algoritmo elegido devuelto por la clase Options
	 */
	public String menuAlgoritmo() {
		String alg = "";
		// entrada por teclado del usuario
		System.out.println("Seleccione un algoritmo de cifrado simétrico: ");
		mostrarAlgoritmosCifrado();

		int entrada = opcion.nextInt();
		switch (entrada) {
		case 1:
			alg = Options.symmetricalAlgorithms[entrada - 1];
			break;
		case 2:
			alg = Options.symmetricalAlgorithms[entrada - 1];
			break;
		case 3:
			alg = Options.symmetricalAlgorithms[entrada - 1];
			break;
		case 4:
			alg = Options.symmetricalAlgorithms[entrada - 1];
			break;
		default:
			System.out.println("ERROR en la seleccion del algoritmo de cifrado...");
			System.out.println("Opcion seleccionada: " + entrada + "\n");
			break;
		}
		System.out.println("Algoritmo seleccionado: " + Options.symmetricalAlgorithms[entrada - 1]);

		return alg;
	}

	public static void main(final String[] args) throws IOException {
		Main main = new Main();
		main.procesoPrincipal();
	}
}