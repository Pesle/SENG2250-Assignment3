public class Main {
	
	//Messages between the client and server are communicated over this link
	public static Connection communicationLink = new Connection();
	
	//Initialise Server - ServerID, SessionID
	private static Server server = new Server(2, 3, communicationLink);
	private static Thread serverThread = new Thread(server);
	
	//Initialise Client - ClientID
	private static Client client = new Client(1, communicationLink);
	private static Thread clientThread = new Thread(client);
	
	
	
	public static void main(String[] args) {
		serverThread.start();
		clientThread.start();
	}

}
