/*
 *  ----C3282137----
 *  Ryan Jobse
 *  SENG2250 S2 2019
 *  Assignment 3
 *  
 *  Main.java
 *  Starts the server and client
 */

import java.util.Scanner;

public class Main {
	
	//Messages between the client and server are communicated over this link
	
	//Port used for communication
	private final static int PORT = 5001;
	
	//Initialise Server - ServerID, SessionID, port
	private static Server server = new Server(456712, 1231234, PORT);
	private static Thread serverThread = new Thread(server);
	
	//Initialise Client - ClientID, port
	private static Client client = new Client(5687456, PORT);
	private static Thread clientThread = new Thread(client);
	
	
	
	public static void main(String[] args) {
		//Display message
		System.out.println(	"Ryan Jobse - C3282137\n"+
							"SENG2250 Assignment 3 2019 S2\n\n"+
							"	-Run Options-\n"+
							"Enter Number to Select Option:\n"+
							"1. Client - 2. Server - 3. Both");
		
		//Check for input
	    Scanner scanner = new Scanner(System.in);
	    int choice = scanner.nextInt();

	    //Decide what to run from the input
	    switch (choice) {
	        case 1:
	        	clientThread.start();
	            break;
	        case 2:
	        	serverThread.start();
	            break;
	        case 3:
	        	//Start server
	        	serverThread.start();
	        	//Wait a little bit
	    		try { Thread.sleep(50); }
	        	catch (InterruptedException e) { e.printStackTrace(); }
	    		//Start client
	    		clientThread.start();
	            break;
	        default:
	            System.out.println("Invalid Option");
	    }
	    scanner.close();

		
	}

}
