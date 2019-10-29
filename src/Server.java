import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Random;

public class Server implements Runnable{
		
	private EncryptionLibrary lib = new EncryptionLibrary();
	
	private final int TTL = 1000;
	
	private Connection commLink;
	private int serverID;
	private int sessionID;
	
	private boolean finished;

	private boolean RSAActive;
	private BigInteger RSAp;
	private BigInteger RSAq;

	private boolean DHVerified;
	private BigInteger DHp;
	private BigInteger DHg;
	private BigInteger DHa;
	private BigInteger DHb;
	
	private boolean AESActive;
	private BigInteger CBCInitialVector;
	private BigInteger CBCPreviousVector;
	
	private BigInteger CTRValue;
	
	Server(int serverID, int sessionID, Connection commLink){
		this.serverID = serverID;
		this.sessionID = sessionID;
		this.commLink = commLink;
		this.RSAActive = false;
		this.AESActive = false;
		this.DHVerified = false;
		this.finished = false;
		Random rand = new SecureRandom();
		RSAp = BigInteger.probablePrime(2048 / 2, rand);
		RSAq = BigInteger.probablePrime(2048 / 2, rand);
		
		//Generate CBCMac Initial Vector
		MessageDigest digest;
		try {
			digest = MessageDigest.getInstance("SHA-256");
			byte[] encodedhash = digest.digest(Integer.toString(rand.nextInt()).getBytes(StandardCharsets.UTF_8));
			CBCInitialVector = new BigInteger(encodedhash);
			CBCPreviousVector = CBCInitialVector;
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		CTRValue = CBCInitialVector.add(BigInteger.ONE);
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
				
				String decodedMessage = "";
				//Decode message
				if(RSAActive) {
					decodedMessage = lib.RSAStringDecode(newMessage);
					System.out.println("Client --> Server (RSA): "+decodedMessage);
				}else if(AESActive){
					decodedMessage = dataExchangeDecrypt(newMessage);
					System.out.println("Client --> Server (AES): "+decodedMessage);
				}
				
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
						send("Setup:"+lib.RSAPublicKey(RSAp, RSAq));
						RSAActive = true;
					}				
				}else {
					//RSA Connection Secured!
					
					//--Receive Step 3
					if(clientID == -1) {
						//Verify RSA connection
						if(decodedMessage.contains("Client_Hello:")) {
							clientID = Integer.parseInt(decodedMessage.substring(13));
							
							//--Transmit Step 4
							send("Server_Hello:"+serverID+","+sessionID);
						}else {
							System.out.println("Server: UNAUTHORISED ATTEMPT");
							send("ERROR");
							finished = true;
						}
						
					//--Receive Step 5 Public Variables
					}else if(DHp == null && DHg == null) {
						
						//Verify RSA Connection
						if(decodedMessage.contains("Client_DH_Public_Vars:Sending")) {
							
							sendACK();
							//Wait for the variables to be sent
							while(true) {
								try { Thread.sleep(2); }
						    	catch (InterruptedException e) { e.printStackTrace(); }
								if(commLink.newMessageFromClient()) {
									BigInteger variables = lib.RSAIntDecode(commLink.receiveFromClient());
									
									try { Thread.sleep(5); }
							    	catch (InterruptedException e) { e.printStackTrace(); }
									
									if(DHp == null) {
										System.out.println("Client --> Server (RSA): DH p Variable:"+variables.toString());
										DHp = variables;
										sendACK();
									}else if(DHg == null) {
										System.out.println("Client --> Server (RSA): DH g Variable:"+variables.toString());
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
							send("Server_DH_Public_Key:" + lib.DiffieHellmanKey(DHg, DHa, DHp).toString());
						}else {
							System.out.println("Server: UNAUTHORISED ATTEMPT");
							commLink.transmitToClient("ERROR");
							finished = true;
						}

					//--Receive Step 5 Client Key
					}else if(DHb == null) {
						if(decodedMessage.contains("Client_DH_Public_Key:Sending")) {
							
							sendACK();
							//Wait for the variables to be sent
							while(true) {
								try { Thread.sleep(1); }
						    	catch (InterruptedException e) { e.printStackTrace(); }
								if(commLink.newMessageFromClient()) {
									BigInteger variables = lib.RSAIntDecode(commLink.receiveFromClient());
									
									try { Thread.sleep(5); }
							    	catch (InterruptedException e) { e.printStackTrace(); }
									
									System.out.println("Client --> Server (RSA): DH Client Key:"+variables.toString());
									DHb = variables;
									lib.setDiffieHellmanB(DHb);
									break;
								}
							}
							//--Transmit Step 5 IV Key for CBC Encryption
							send("Server_CBC_IV:"+CBCInitialVector.toString());
							RSAActive = false;
							AESActive = true;
						}
						
					}else if(!DHVerified) {
						if(decodedMessage.contains("Client_DH_Verify")) {
							DHVerified = true;
							//64 Bytes Message
							send(dataExchangeEncrypt(lib.convertToBigInt("Server_DH_Verify")));
						}else {
							System.out.println("Server: DH Key Not Correct!");
							finished = true;
						}
						
					}else {
						
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
	
	private void send(String message) {
		try { Thread.sleep(2); }
    	catch (InterruptedException e) { e.printStackTrace(); }
		commLink.transmitToClient(message);
		try { Thread.sleep(2); }
		catch (InterruptedException e) { e.printStackTrace(); }
	}
	
	private void sendACK() {
		System.out.println("Client <-- Server: Server_ACK");
		send("Server_ACK");
	}
	
	private String dataExchangeDecrypt(String input) {
		String[] message = input.split(",");
		byte[] result = new byte[message.length];
		for(int i = 0; i < message.length; i++) {
			result[i] = (byte)Integer.parseInt(message[i]);
		}
		BigInteger AESMessage = new BigInteger(lib.AESDecrypt(new BigInteger(result)));
		System.out.println("CBC " + CBCPreviousVector.toString());
		BigInteger CBCMessage = lib.CBCDecrypt(CBCPreviousVector, AESMessage);
		System.out.println("CTR " + CTRValue.toString());
		BigInteger CTRMessage = lib.CTRDecrypt(CBCMessage, CTRValue);
		String decodedMessage = lib.convertFromBigInt(CTRMessage);
		CBCPreviousVector = CBCMessage;
		CTRValue = CTRValue.add(BigInteger.ONE);
		return decodedMessage;
	}
	
	private String dataExchangeEncrypt(BigInteger input) {
		System.out.println("CTR " + CTRValue.toString());
		BigInteger CTRMessage = lib.CTREncrypt(input, CTRValue);
		System.out.println("CBC " + CBCPreviousVector.toString());
		BigInteger CBCMessage = lib.CBCEncrypt(CBCPreviousVector, CTRMessage);
		CTRValue = CTRValue.add(BigInteger.ONE);
		System.out.println("Len "+ CBCMessage.toByteArray().length);
		byte[] result = lib.AESEncrypt(CBCMessage);
		CBCPreviousVector = CBCMessage;
		String message = "";
		for(int i = 0; i < result.length; i++) {
			message += result[i];
			if(i < result.length-1) {
				message += ",";
			}
		}
		return message;
	}
	
}
