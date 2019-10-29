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
	
	public void transmitToClient(String message) {
		connectionToClient.addLast(message);
		try { Thread.sleep(2); }
    	catch (InterruptedException e) { e.printStackTrace(); }
		newMessageFromServer = true;		
		try { Thread.sleep(2); }
    	catch (InterruptedException e) { e.printStackTrace(); }
	}
	
	public void transmitToServer(String message) {
		connectionToServer.addLast(message);
		try { Thread.sleep(2); }
    	catch (InterruptedException e) { e.printStackTrace(); }
		newMessageFromClient = true;
		try { Thread.sleep(2); }
    	catch (InterruptedException e) { e.printStackTrace(); }
	}
	
	public String receiveFromClient() {
		newMessageFromServer = false;
		try { Thread.sleep(2); }
    	catch (InterruptedException e) { e.printStackTrace(); }
		return connectionToServer.getLast();
	}
	
	public String receiveFromServer() {
		newMessageFromClient = false;
		try { Thread.sleep(2); }
    	catch (InterruptedException e) { e.printStackTrace(); }
		return connectionToClient.getLast();
	}
	
	public boolean newMessageFromServer() {
		return newMessageFromServer;
	}
	
	public boolean newMessageFromClient() {
		return newMessageFromClient;
	}
	
	public String toStringClient() {
		String result = "";
		for(int i = 0; i < connectionToClient.size(); i++) {
			result += connectionToClient.get(i)+"\n";
		}
		return result;
	}
	
	public String toStringServer() {
		String result = "";
		for(int i = 0; i < connectionToServer.size(); i++) {
			result += connectionToServer.get(i)+"\n";
		}
		return result;
	}
}
