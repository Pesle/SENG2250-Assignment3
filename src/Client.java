
public class Client {
	
	private String RSAPublicKey;
	
	private int clientID = 1;
	private Server server = new Server(this);

	public static void main(String[] args) {
		server.SetupRequest("HELLO");
	}
	
	//Static issue, maybe make a main class and let server and client talk that way
	

}
