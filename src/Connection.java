import java.util.LinkedList;

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
		try { Thread.sleep(2); }
    	catch (InterruptedException e) { e.printStackTrace(); }
		newMessageFromServer = true;		
		try { Thread.sleep(2); }
    	catch (InterruptedException e) { e.printStackTrace(); }
	}
	
	void transmitToServer(String message) {
		connectionToServer.addLast(message);
		try { Thread.sleep(2); }
    	catch (InterruptedException e) { e.printStackTrace(); }
		newMessageFromClient = true;
		try { Thread.sleep(2); }
    	catch (InterruptedException e) { e.printStackTrace(); }
	}
	
	String receiveFromClient() {
		newMessageFromServer = false;
		try { Thread.sleep(2); }
    	catch (InterruptedException e) { e.printStackTrace(); }
		return connectionToServer.getLast();
	}
	
	String receiveFromServer() {
		newMessageFromClient = false;
		try { Thread.sleep(2); }
    	catch (InterruptedException e) { e.printStackTrace(); }
		return connectionToClient.getLast();
	}
	
	boolean newMessageFromServer() {
		return newMessageFromServer;
	}
	
	boolean newMessageFromClient() {
		return newMessageFromClient;
	}
}
