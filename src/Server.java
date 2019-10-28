import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Random;

public class Server implements Runnable{
		
	private final int TTL = 1000;
	
	private Connection commLink;
	private int serverID;
	private int sessionID;
	private boolean finished;

	private BigInteger RSAp;
	private BigInteger RSAq;
	private BigInteger RSAn;
	private BigInteger RSAm;
	private BigInteger RSAe;
	private BigInteger RSAd;
	
	private BigInteger DHp;
	private BigInteger DHg;
	
	private BigInteger DHClientKey;
	private BigInteger DHa;
	
	Server(int serverID, int sessionID, Connection commLink){
		this.serverID = serverID;
		this.sessionID = sessionID;
		this.commLink = commLink;
		this.finished = false;
		Random rand = new SecureRandom();
		RSAp = BigInteger.probablePrime(2048 / 2, rand);
		RSAq = BigInteger.probablePrime(2048 / 2, rand);
	}
	
	@Override
	public void run() {
		boolean setupFinished = false;
		int clientID = -1;
		
		int timeout = 0;
		
		//Loop while not finished
		while(finished != true) {
			
			//Add to timeout
			timeout++;
			
			//Sleep the thread for stability
			try { Thread.sleep(5); }
	    	catch (InterruptedException e) { e.printStackTrace(); }
			
			//Check if there is a new message from client
			if(commLink.newMessageFromClient()) {
				
				//Read the new message
				String newMessage = commLink.receiveFromClient();
				
				try { Thread.sleep(5); }
		    	catch (InterruptedException e) { e.printStackTrace(); }
				
				//Reset timeout
				timeout = 0;
				
				//--Receive Step 1
				if(!setupFinished) {
					System.out.println("Client --> Server: "+newMessage);
					
					if(newMessage.contains("Setup_Request:")) {
						setupFinished = true;

						try { Thread.sleep(2); }
				    	catch (InterruptedException e) { e.printStackTrace(); }
						
						//--Transmit Step 2
						//Send Client the RSA Public Key
						commLink.transmitToClient("Setup:"+RSAPublicKey());
					}				
				}else {
					//SSL Connection Secured!
					//Decode message
					String decodedMessage = RSAStringDecode(newMessage);
					System.out.println("Client --> Server (SSL): "+decodedMessage);
					
					//--Receive Step 3
					if(clientID == -1) {
						//Verify RSA connection
						if(decodedMessage.contains("Client_Hello:")) {
							clientID = Integer.parseInt(decodedMessage.substring(13));
							
							//--Transmit Step 4
							commLink.transmitToClient("Server_Hello:"+serverID+","+sessionID);
						}else {
							System.out.println("Server: UNAUTHORISED ATTEMPT");
							commLink.transmitToClient("ERROR");
							finished = true;
						}
						
					//--Receive Step 5 Public Variables
					}else if(DHp == null && DHg == null) {
						//Verify RSA Connection
						if(decodedMessage.contains("Client_DH_Public_Vars:Sending")) {
							
							//Wait for the variables to be sent
							while(true) {
								try { Thread.sleep(1); }
						    	catch (InterruptedException e) { e.printStackTrace(); }
								if(commLink.newMessageFromClient()) {
									BigInteger variables = RSAIntDecode(commLink.receiveFromClient());
									
									try { Thread.sleep(5); }
							    	catch (InterruptedException e) { e.printStackTrace(); }
									
									if(DHp == null) {
										System.out.println("Client --> Server (SSL): DH p Variable:"+variables.toString());
										DHp = variables;
									}else if(DHg == null) {
										System.out.println("Client --> Server (SSL): DH g Variable:"+variables.toString());
										DHg = variables; 
										break;
									}
								}
							}
							
							//Generate Private Variable
							Random rand = new SecureRandom();
							do {  //Make sure that the DHa is smaller then P
							    DHa = new BigInteger(DHp.toString().length(), rand);
							} while (DHa.compareTo(DHp) >= 0);
							
							//--Transmit Step 5 Server Key
							commLink.transmitToClient("Server_DH_Public_Key:"+DiffieHellmanKey());
						}else {
							System.out.println("Server: UNAUTHORISED ATTEMPT");
							commLink.transmitToClient("ERROR");
							finished = true;
						}
						
					//--Receive Step 5 Client Key
					}else if(DHClientKey == null) {
						if(decodedMessage.contains("Client_DH_Public_Key:Sending")) {
							
							//Wait for the variables to be sent
							while(true) {
								try { Thread.sleep(1); }
						    	catch (InterruptedException e) { e.printStackTrace(); }
								if(commLink.newMessageFromClient()) {
									BigInteger variables = RSAIntDecode(commLink.receiveFromClient());
									
									try { Thread.sleep(5); }
							    	catch (InterruptedException e) { e.printStackTrace(); }
									
									System.out.println("Client --> Server (SSL): DH Client Key:"+variables.toString());
									DHClientKey = variables;
									break;
								}
							}
						}
							
						if(true) {
							System.out.println("Server: Keys Verified!");
						}else {
							System.out.println("Server: DH Key Error!");
						}
					}else {
						finished = true;
						System.out.println("Server: FINISHED");
					}
				}
			}
			
			//Check if timeout occurs
			if(timeout > TTL) {
				System.out.println("Server: TIMEOUT");
				break;
			}
		}
	}
	
	private String DiffieHellmanKey() {
		return DHg.modPow(DHa, DHp).toString();
	}
	
	private String RSAPublicKey() {
		String result = "";
		RSAn = RSAp.multiply(RSAq);
		RSAe = new BigInteger("65537");
		RSAm = (RSAp.subtract(BigInteger.ONE)).multiply(RSAq.subtract(BigInteger.ONE));
		RSAd = RSAe.modInverse(RSAm);
		
		result = RSAn.toString()+","+RSAe.toString();
		return result;
	}
	
	private String RSAStringDecode(String input) {		
		//Convert Input String to Big Integer
		BigInteger in = new BigInteger(input);
		
		//Decode the RSA with private keys
		BigInteger result = in.modPow(RSAd, RSAn);
		
		//Convert bytes back to UTF-8
		byte[] array = result.toByteArray();
		String message = new String(array, StandardCharsets.US_ASCII);
		return message;
	}
	
	private BigInteger RSAIntDecode(String input) {		
		//Convert Input String to Big Integer
		BigInteger in = new BigInteger(input);
		
		//Decode the RSA with private keys
		BigInteger result = in.modPow(RSAd, RSAn);
		
		return result;
	}
	
}
