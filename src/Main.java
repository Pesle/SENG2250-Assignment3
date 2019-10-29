public class Main {
	
	//Messages between the client and server are communicated over this link
	public static Connection communicationLink = new Connection();
	
	//Initialise Server - ServerID, SessionID
	private static Thread server = new Thread(new Server(2, 3, communicationLink));
	
	//Initialise Client - ClientID
	private static Thread client = new Thread(new Client(1, communicationLink));
	
	
	
	public static void main(String[] args) {
		server.start();
		client.start();
	}

}
