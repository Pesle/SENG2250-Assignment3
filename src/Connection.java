import java.util.LinkedList;
import java.util.concurrent.Semaphore;

public class Connection {
	
	private Semaphore simplex = new Semaphore(1, true);
	
	private LinkedList<String> connectionToClient;
	private LinkedList<String> connectionToServer;
	
	private boolean newMessageFromClient;
	private boolean newMessageFromServer;
	
	Connection(){
		 connectionToClient = new LinkedList<String>();
		 connectionToServer = new LinkedList<String>();
		 newMessageFromClient = false;
		 newMessageFromServer = false;
	}
	
	void transmitToClient(String message) {
		try {
			simplex.acquire();
			connectionToClient.addLast(message);
			newMessageFromServer = true;
		} catch (InterruptedException e) {
			e.printStackTrace();
		}
		
	}
	
	void transmitToServer(String message) {
		try {
			simplex.acquire();
			connectionToServer.addLast(message);
			newMessageFromClient = true;
		} catch (InterruptedException e) {
			e.printStackTrace();
		}
	}
	
	String receiveFromClient() {
		newMessageFromServer = false;
		return connectionToServer.getLast();
	}
	
	String receiveFromServer() {
		newMessageFromClient = false;
		return connectionToClient.getLast();
	}
	
	boolean newMessageFromServer() {
		return newMessageFromServer;
	}
	
	boolean newMessageFromClient() {
		return newMessageFromClient;
	}
}
