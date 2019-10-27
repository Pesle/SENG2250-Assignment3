import java.io.UnsupportedEncodingException;
import java.math.BigInteger;

public class Client implements Runnable{
	
	private Connection commLink;
	private int clientID;
	private BigInteger RSAn;
	private BigInteger RSAe;
	
	private boolean finished;

	Client(int clientID, Connection commLink){
		finished = false;
		this.clientID = clientID;
		this.commLink = commLink;
	}
	
	
	@Override
	public void run() {
		commLink.transmitToServer("Setup_Request:Hello");
		while(finished != true) {
			if(commLink.newMessageFromServer()) {
				String newMessage = commLink.receiveFromServer();
				if(RSAn == null && RSAe == null) {
					if(newMessage.contains("Setup:")) {
						String[] message = newMessage.split(",");
						RSAn = new BigInteger(message[1]);
						RSAe = new BigInteger(message[2]);
					}
					commLink.transmitToServer(RSAEncode("100").toString());
				}else {
					finished = true;
				}
			}
			try { Thread.sleep(10); }
	    	catch (InterruptedException e) { e.printStackTrace(); }
		}
	}
	
	private BigInteger RSAEncode(String input) {
		BigInteger message = new BigInteger(input);
		//BigInteger message = null;
		//try {
		//	message = new BigInteger(input.getBytes("US-ASCII"));
		//} catch (UnsupportedEncodingException e) {
		//	e.printStackTrace();
		//}
		return message.modPow(RSAe, RSAn);
	}
}
