import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Random;


public class Client implements Runnable{
	
	private EncryptionLibrary lib = new EncryptionLibrary();
	
	private final int TTL = 1000;
	
	private Connection commLink;
	private int clientID;
	private BigInteger RSAn;
	private BigInteger RSAe;
	
	private boolean DHVerified;
	private BigInteger DHServerKey;
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
	
	private BigInteger CBCInitialVector;
	private BigInteger CBCPreviousVector;
	
	private BigInteger CTRValue;
	
	private boolean finished;

	Client(int clientID, Connection commLink){
		finished = false;
		this.clientID = clientID;
		this.commLink = commLink;
		DHVerified = false;
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
				
				if(CBCInitialVector == null)
					System.out.println("Client <-- Server: "+newMessage);
				
				//--Receive Step 2
				if(RSAn == null && RSAe == null) {
					if(newMessage.contains("Setup:")) {
						String[] message = newMessage.substring(6).split(",");
						RSAn = new BigInteger(message[0]);
						RSAe = new BigInteger(message[1]);
						lib.setRSAPublicVars(RSAn, RSAe);
					}
					
					//--Transmit Step 3
					commLink.transmitToServer(lib.RSAStringEncode("Client_Hello:"+clientID));
					
				}else {
					//SSL Connection Secured!
					
					//--Receive Step 4
					if(serverID == -1 && sessionID == -1) {
						if(newMessage.contains("Server_Hello:")) {
							String[] message = newMessage.substring(13).split(",");
							serverID = Integer.parseInt(message[0]);
							sessionID = Integer.parseInt(message[1]);
							
							//--Transmit Step 5 Public Variables
							commLink.transmitToServer(lib.RSAStringEncode("Client_DH_Public_Vars:Sending"));
							
							try { Thread.sleep(2); }
					    	catch (InterruptedException e) { e.printStackTrace(); }
							
							while(true) {
								try { Thread.sleep(1); }
						    	catch (InterruptedException e) { e.printStackTrace(); }
								if(commLink.newMessageFromServer()) {
									if(commLink.receiveFromServer().equals("Server_ACK")) {
										commLink.transmitToServer(lib.RSAIntEncode(DHp));
										break;
									}else {
										System.out.println("Client: Error Occured!");
										finished = true;
										break;
									}
								}
							}
							
							try { Thread.sleep(2); }
					    	catch (InterruptedException e) { e.printStackTrace(); }
							
							while(true) {
								try { Thread.sleep(1); }
						    	catch (InterruptedException e) { e.printStackTrace(); }
								if(commLink.newMessageFromServer()) {
									if(commLink.receiveFromServer().equals("Server_ACK")){
										commLink.transmitToServer(lib.RSAIntEncode(DHg));
										break;
									}else {
										System.out.println("Client: Error Occured!");
										finished = true;
										break;
									}
								}
							}
							
						}else {
							System.out.println("Client: Error Occured!");
							finished = true;
							break;
						}
						
					//--Receive Step 5 Public Key
					}else if(DHServerKey == null) {
						if(newMessage.contains("Server_DH_Public_Key:")) {
							DHServerKey = new BigInteger(newMessage.substring(21));
							lib.setDiffieHellmanB(DHServerKey);
							//Generate Private Variable
							Random rand = new SecureRandom();
							do {  //Make sure that the DHa is smaller then P
							    DHb = new BigInteger(DHp.toString().length(), rand);
							} while (DHb.compareTo(DHp) >= 0);
							
							//--Transmit Step 5 Public Key
							commLink.transmitToServer(lib.RSAStringEncode("Client_DH_Public_Key:Sending"));
							
							try { Thread.sleep(2); }
					    	catch (InterruptedException e) { e.printStackTrace(); }
							
							while(true) {
								try { Thread.sleep(1); }
						    	catch (InterruptedException e) { e.printStackTrace(); }
								if(commLink.newMessageFromServer()) {
									if(commLink.receiveFromServer().equals("Server_ACK")) {
										commLink.transmitToServer(lib.RSAIntEncode(lib.DiffieHellmanKey(DHg, DHb, DHp)));
										try { Thread.sleep(2); }
								    	catch (InterruptedException e) { e.printStackTrace(); }
										break;
									}else {
										System.out.println("Client: Error Occured!");
										finished = true;
										break;
									}
								}
							}
						}else {
							System.out.println("Client: Error Occured!");
							finished = true;
							break;
						}
					}else if(CBCInitialVector == null) {
						if(newMessage.contains("Server_CBC_IV:")) {
							CBCInitialVector = new BigInteger(newMessage.substring(14));
							CBCPreviousVector = CBCInitialVector;
							
							CTRValue = CBCInitialVector.add(BigInteger.ONE);;
							
							//--Transmit Step 6 Test Message
							//Encrypt with CBC first, then encrypt with AES
							
							commLink.transmitToServer(dataExchangeEncrypt(lib.convertToBigInt("Client_DH_Verify")));
						}
					}else if(!DHVerified) {
						String decodedMessage = dataExchangeDecrypt(newMessage);
						System.out.println("Client <-- Server (AES): "+decodedMessage);
						if(decodedMessage.contains("Server_DH_Verify")) {
							
							DHVerified = true;
							//--Transmit Step 7 Data Exchange
							//Encrypt then send
							commLink.transmitToServer(dataExchangeEncrypt(lib.convertToBigInt("A user interface is like a joke. You shouldnt have to explain it")));
						}else {
							System.out.println("Client: DH Key Not Correct!");
							finished = true;
						}
					}else {
						String decodedMessage = dataExchangeDecrypt(newMessage);
						System.out.println("Client <-- Server (AES): "+decodedMessage);
						finished = true;
					}
					
				}
			}
			if(timeout > TTL) {
				System.out.println("Client: TIMEOUT");
				break;
			}
		}
		finished = true;
		System.out.println("Client: STOPPED");
	}
	
	private String dataExchangeDecrypt(String input) {
		String[] message = input.split(",");
		byte[] result = new byte[message.length];
		for(int i = 0; i < message.length; i++) {
			result[i] = (byte)Integer.parseInt(message[i]);
		}
		BigInteger AESMessage = new BigInteger(lib.AESDecrypt(new BigInteger(result)));
		BigInteger CBCMessage = lib.CBCDecrypt(CBCPreviousVector, AESMessage);
		BigInteger CTRMessage = lib.CTRDecrypt(CBCMessage, CTRValue);
		String decodedMessage = lib.convertFromBigInt(CTRMessage);
		CBCPreviousVector = CBCMessage;
		CTRValue = CTRValue.add(BigInteger.ONE);
		return decodedMessage;
	}
	
	private String dataExchangeEncrypt(BigInteger input) {
		BigInteger CTRMessage = lib.CTREncrypt(input, CTRValue);
		BigInteger CBCMessage = lib.CBCEncrypt(CBCPreviousVector, CTRMessage);
		CTRValue = CTRValue.add(BigInteger.ONE);
		byte[] result = lib.AESEncrypt(CBCMessage);
		CBCPreviousVector = CTRMessage;
		String message = "";
		for(int i = 0; i < result.length; i++) {
			message += result[i];
			if(i < result.length-1) {
				message += ",";
			}
		}
		return message;
	}
	
	public boolean isFinished() {
		return finished;
	}

}
