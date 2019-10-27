import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Random;

public class Client implements Runnable{
	
	private final int TTL = 1000;
	
	private Connection commLink;
	private int clientID;
	private BigInteger RSAn;
	private BigInteger RSAe;
	
	private BigInteger DHa;
	private BigInteger DHb;
	
	private BigInteger DHp = new BigInteger("17801190547854226652823756245015999014523215636912067427327445031444" + 
			"28657887370207706126952521234630795671567847784664499706507709207278" + 
			"57050009668388144034129745221171818506047231150039301079959358067395" + 
			"34871706631980226201971496652413506094591370759495651467285569060679" + 
			"4135837542707371727429551343320695239");
	private BigInteger DHg = new BigInteger("17406820753240209518581198012352343653860449079456135097849583104059" + 
			"99534884558231478515974089409507253077970949157594923683005742524387" + 
			"61037084473467180148876118103083043754985190983472601550494691329488" + 
			"08339549231385000036164648264460849230407872181895999905649609776936" + 
			"8017749273708962006689187956744210730");
	
	private boolean finished;

	Client(int clientID, Connection commLink){
		finished = false;
		this.clientID = clientID;
		this.commLink = commLink;
	}
	
	
	@Override
	public void run() {
		int serverID = -1, sessionID = -1;
		
		int timeout = 0;
		
		//--Transmit Step 1
		commLink.transmitToServer("Setup_Request:Hello");
		
		while(finished != true) {
			timeout++;
			try { Thread.sleep(5); }
	    	catch (InterruptedException e) { e.printStackTrace(); }
			
			if(commLink.newMessageFromServer()) {
				timeout = 0;
				String newMessage = commLink.receiveFromServer();
				
				try { Thread.sleep(5); }
		    	catch (InterruptedException e) { e.printStackTrace(); }
				
				System.out.println("Client <-- Server: "+newMessage);
				
				//--Receive Step 2
				if(RSAn == null && RSAe == null) {
					if(newMessage.contains("Setup:")) {
						String[] message = newMessage.substring(6).split(",");
						RSAn = new BigInteger(message[0]);
						RSAe = new BigInteger(message[1]);
					}
					
					//--Transmit Step 3
					commLink.transmitToServer(RSAEncode("Client_Hello:"+clientID));
					
				}else {
					//SSL Connection Secured!
					
					//--Receive Step 4
					if(serverID == -1 && sessionID == -1) {
						if(newMessage.contains("Server_Hello:")) {
							String[] message = newMessage.substring(13).split(",");
							serverID = Integer.parseInt(message[0]);
							sessionID = Integer.parseInt(message[1]);
							commLink.transmitToServer(RSAEncode("Client_DH_Public_Vars:"+DHp.toString()+","+DHg.toString()));
						}else {
							System.out.println("Client: Error Occured!");
							finished = true;
							break;
						}
						
					//--Receive Step 5 Public Key
					}else if(DHb == null) {
						if(newMessage.contains("Server_DH_Public_Key:")) {
							DHb = new BigInteger(newMessage.substring(13));
							
							//Generate Private Variable
							Random rand = new SecureRandom();
							do {  //Make sure that the DHa is smaller then P
							    DHb = new BigInteger(DHp.toString().length(), rand);
							} while (DHb.compareTo(DHp) >= 0);
							
							//--Transmit Step 5 Public Key
							commLink.transmitToServer(RSAEncode("Client_DH_Public_Key:"+DiffieHellmanKey()));
						}else {
							System.out.println("Client: Error Occured!");
							finished = true;
							break;
						}
					}else {
						finished = true;
						System.out.println("Client: FINISHED");
					}
				}
			}
			if(timeout > TTL) {
				System.out.println("Client: TIMEOUT");
				break;
			}
		}
	}
	
	private String DiffieHellmanKey() {
		
		return null;
	}
	
	private String RSAEncode(String input) {
		BigInteger message = null;
		//Try to change the input from UTF-8 to bytes which converts to bigIntegers
		try {
			message = new BigInteger(input.getBytes("UTF-8"));
		} catch (UnsupportedEncodingException e) {
			e.printStackTrace();
		}
		//Encode the message with the public key
		return message.modPow(RSAe, RSAn).toString();
	}
}
