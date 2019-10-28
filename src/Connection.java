import java.util.LinkedList;
import java.util.concurrent.Semaphore;

public class Connection {
	
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
		connectionToClient.addLast(message);
		newMessageFromServer = true;		
		try { Thread.sleep(5); }
    	catch (InterruptedException e) { e.printStackTrace(); }
	}
	
	void transmitToServer(String message) {
		connectionToServer.addLast(message);
		newMessageFromClient = true;
		try { Thread.sleep(5); }
    	catch (InterruptedException e) { e.printStackTrace(); }
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
