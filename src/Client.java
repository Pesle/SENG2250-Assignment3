/*
 *  ----C3282137----
 *  Ryan Jobse
 *  SENG2250 S2 2019
 *  Assignment 3
 *  
 *  Client.java
 *  Client part of the assignment
 */

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Random;


public class Client implements Runnable{
	
	private EncryptionLibrary lib = new EncryptionLibrary();
	private Connection commLink = new Connection();
	
	//Time to live
	private final int TTL = 1000;
	
	//Port for the connection
	private int port;
	
	//Client ID
	private int clientID;
	
	//RSA Public Values
	private BigInteger RSAn;
	private BigInteger RSAe;
	
	//DiffieHellman Values
	private boolean DHVerified;	//If DiffieHellman is verified
	private BigInteger DHServerKey;
	private BigInteger DHb;
	//P and G Constants as per Assignment Specs
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
	
	//CBCMac Values
	private BigInteger CBCInitialVector;
	private BigInteger CBCPreviousVector;
	
	//CTR Value
	private BigInteger CTRValue;
	
	private boolean finished; //If process is finished

	Client(int clientID, int port){
		//Initialise Values
		finished = false;
		this.clientID = clientID;
		this.port = port;
		DHVerified = false;
	}
	
	
	@Override
	public void run() {
		System.out.println("Client: Connecting...");
		
		int timeout = 0;
		
		//Try connecting to a Server
		//Can timeout to stop thread
		boolean connected = false;
		while(!connected) {
			timeout++;
			//Create client socket
			connected = commLink.connectClient("localhost", port);
			if(timeout > TTL) {
				System.out.println("Client: TIMEOUT");
				finished = true;
				break;
			}
		}
		int serverID = -1, sessionID = -1;
		
		//If Connected
		if(!finished) {
			System.out.println("Client: Connected");			
			
			//--Transmit Step 1
			commLink.transmit("Setup_Request:Hello");
		}
		
		//Loop while not finished
		while(finished != true) {
			
			//Add to timeout
			timeout++;
			
			//Sleep the thread for stability
			try { Thread.sleep(5); }
	    	catch (InterruptedException e) { e.printStackTrace(); }
			
			//Check if there is a new message from the server
			if(commLink.newMessage()) {
				timeout = 0;
				
				//Read the new message
				String newMessage = commLink.receive();
				
				try { Thread.sleep(5); }
		    	catch (InterruptedException e) { e.printStackTrace(); }
				
				//If not encrypted, print the message
				if(CBCInitialVector == null)
					System.out.println("Client <-- Server: "+newMessage);
				
				//--Receive Step 2
				if(RSAn == null && RSAe == null) {
					if(newMessage.contains("Setup:")) {
						//Store RSA Variables from message
						String[] message = newMessage.substring(6).split(",");
						RSAn = new BigInteger(message[0]);
						RSAe = new BigInteger(message[1]);
						lib.setRSAPublicVars(RSAn, RSAe);
					}
					
					//--Transmit Step 3
					commLink.transmit(lib.RSAStringEncode("Client_Hello:"+clientID));
					
				}else {
					//RSA Connection Secured!
					
					//--Receive Step 4
					if(serverID == -1 && sessionID == -1) {
						if(newMessage.contains("Server_Hello:")) {
							//Store server id and Session ID
							String[] message = newMessage.substring(13).split(",");
							serverID = Integer.parseInt(message[0]);
							sessionID = Integer.parseInt(message[1]);
							
							//--Transmit Step 5 Public Variables
							//Tell the Server that you want to send DH Public Vars
							commLink.transmit(lib.RSAStringEncode("Client_DH_Public_Vars:Sending"));
							
							
							try { Thread.sleep(2); }
					    	catch (InterruptedException e) { e.printStackTrace(); }
							
							//READ-ME
							//Explanation for this mess in Server.java line 168
							
							//Wait for a reply from the server
							while(true) {
								try { Thread.sleep(1); }
						    	catch (InterruptedException e) { e.printStackTrace(); }
								
								//Wait for Acknowledgement from server
								if(commLink.newMessage()) {
									if(commLink.receive().equals("Server_ACK")) {
										System.out.println("Client <-- Server: Server_ACK");
										//Send DHp
										commLink.transmit(lib.RSAIntEncode(DHp));
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
							
							//Wait for a reply from the server
							while(true) {
								try { Thread.sleep(1); }
						    	catch (InterruptedException e) { e.printStackTrace(); }
								
								//Wait for Acknowledgement from server
								if(commLink.newMessage()) {
									if(commLink.receive().equals("Server_ACK")){
										System.out.println("Client <-- Server: Server_ACK");
										//Send DHg
										commLink.transmit(lib.RSAIntEncode(DHg));
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
							//Tell the server you want to send the DiffieHellman public key
							commLink.transmit(lib.RSAStringEncode("Client_DH_Public_Key:Sending"));
							
							try { Thread.sleep(2); }
					    	catch (InterruptedException e) { e.printStackTrace(); }
							
							//READ-ME
							//Explanation for this mess in Server.java line 168
							
							//Wait for reply from Server
							while(true) {
								try { Thread.sleep(1); }
						    	catch (InterruptedException e) { e.printStackTrace(); }
								
								//Wait for Acknowledgement from server
								if(commLink.newMessage()) {
									if(commLink.receive().equals("Server_ACK")) {
										System.out.println("Client <-- Server: Server_ACK");
										
										//Send DiffieHellman Public Key
										commLink.transmit(lib.RSAIntEncode(lib.DiffieHellmanKey(DHg, DHb, DHp)));
										
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
						//--Receive Step 6 CBC Initial Vector
						if(newMessage.contains("Server_CBC_IV:")) {
							CBCInitialVector = new BigInteger(newMessage.substring(14));
							//Set Initial Vector
							CBCPreviousVector = CBCInitialVector;
							
							CTRValue = CBCInitialVector.add(BigInteger.ONE);;
							
							//--Transmit Step 6 Test Message
							//Encrypt with CTR, CBC and AES
							
							commLink.transmit(dataExchangeEncrypt(lib.convertToBigInt("Client_DH_Verify")));
						}
					}else if(!DHVerified) {
						//--Received Step 5 DiffieHellman Verification
						
						//Decode message
						String decodedMessage = dataExchangeDecrypt(newMessage);
						System.out.println("Client <-- Server (AES): "+decodedMessage);
						if(decodedMessage.contains("Server_DH_Verify")) {
							
							DHVerified = true;
							
							//--Transmit Step 7 Data Exchange
							//Encrypt then send
							commLink.transmit(dataExchangeEncrypt(lib.convertToBigInt("A user interface is like a joke. You shouldnt have to explain it")));
						}else {
							System.out.println("Client: DH Key Not Correct!");
							finished = true;
						}
					}else {
						//Receive Message from Server
						String decodedMessage = dataExchangeDecrypt(newMessage);
						System.out.println("Client <-- Server (AES): "+decodedMessage);
					}
					
				}
			}
			if(timeout > TTL) {
				System.out.println("Client: TIMEOUT");
				break;
			}
		}
		commLink.closeConnections();
		finished = true;
		System.out.println("Client: STOPPED");
	}
	
	//Decrypt the AES, CBC and CTR messages
	private String dataExchangeDecrypt(String input) {
		//I had issues sending by Strings as it would use illegal characters
		//So i had to send by bytes
		
		//Split the message by commas
		String[] message = input.split(",");
		//Rebuild byte array
		byte[] result = new byte[message.length];
		for(int i = 0; i < message.length; i++) {
			result[i] = (byte)Integer.parseInt(message[i]);
		}
		//Decrypt AES from message
		BigInteger AESMessage = new BigInteger(lib.AESDecrypt(new BigInteger(result)));
		//Decrypt message from CBC
		BigInteger CBCMessage = lib.CBCDecrypt(CBCPreviousVector, AESMessage);
		//Decrypt message from CTR
		BigInteger CTRMessage = lib.CTRDecrypt(CBCMessage, CTRValue);
		//Convert the message back to a String
		String decodedMessage = lib.convertFromBigInt(CTRMessage);
		//Set previous vector to CBCMessage
		CBCPreviousVector = CBCMessage;
		//Add one to CTRValue
		CTRValue = CTRValue.add(BigInteger.ONE);
		return decodedMessage;
	}
	
	//Encrypt with AES, CBC and CTR
	private String dataExchangeEncrypt(BigInteger input) {
		//Encrypt message with CTR
		BigInteger CTRMessage = lib.CTREncrypt(input, CTRValue);
		//Encrypt message with CBC
		BigInteger CBCMessage = lib.CBCEncrypt(CBCPreviousVector, CTRMessage);
		//Increase CTR Value by one
		CTRValue = CTRValue.add(BigInteger.ONE);
		//Encrypt message with AES
		byte[] result = lib.AESEncrypt(CBCMessage);
		//Set previous vector to CTRMessage
		CBCPreviousVector = CTRMessage;
		//Deconstruct bytes to comma seperated string
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
