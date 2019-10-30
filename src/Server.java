/*
 *  ----C3282137----
 *  Ryan Jobse
 *  SENG2250 S2 2019
 *  Assignment 3
 *  
 *  Server.java
 *  Server part of the assignment
 */

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Random;

public class Server implements Runnable{
		
	private EncryptionLibrary lib = new EncryptionLibrary();
	private Connection commLink = new Connection();
	
	//time to live
	private final int TTL = 1000;
	
	//Port number for connection
	private int port;
	
	//Server and session id
	private int serverID;
	private int sessionID;
	
	//Whether the process has finished
	private boolean finished;

	//RSA Values
	private boolean RSAActive;	//If decoding by RSA
	private BigInteger RSAp;
	private BigInteger RSAq;

	//DiffieHellman Values
	private boolean DHVerified;	//If DH has been verified
	private BigInteger DHp;
	private BigInteger DHg;
	private BigInteger DHa;
	private BigInteger DHb;
	
	private boolean AESActive;	//If decoding by AES
	
	//CBCMAC Values
	private BigInteger CBCInitialVector;
	private BigInteger CBCPreviousVector;
	
	//CTR Value
	private BigInteger CTRValue;
	
	Server(int serverID, int sessionID, int port){
		//Set values
		this.serverID = serverID;
		this.sessionID = sessionID;
		this.port = port;
		this.RSAActive = false;
		this.AESActive = false;
		this.DHVerified = false;
		this.finished = false;
		
		//Set RSA Values to randoms
		Random rand = new SecureRandom();
		RSAp = BigInteger.probablePrime(2048 / 2, rand);
		RSAq = BigInteger.probablePrime(2048 / 2, rand);
		
		//Generate CBCMac Initial Vector
		Random rd = new Random();
	    byte[] randBytes = new byte[16];
	    rd.nextBytes(randBytes);
		CBCInitialVector = new BigInteger(randBytes);
		CBCPreviousVector = CBCInitialVector;
		
		//Set CTRValue to CBCInitialVector plus 1
		CTRValue = CBCInitialVector.add(BigInteger.ONE);
	}
	
	@Override
	public void run() {
		System.out.println("Server: Connecting...");
		
		int timeout = 0;
		
		//Try connecting to a Client
		//Can timeout to stop thread
		boolean connected = false;
		while(!connected) {
			timeout++;
			//Create server socket
			connected = commLink.connectServer(port);
			if(timeout > TTL) {
				System.out.println("Server: TIMEOUT");
				finished = true;
				break;
			}
		}
		//If connected
		if(!finished) {
			System.out.println("Server: Connected");
		}
		
		boolean setupFinished = false;
		int clientID = -1;
		
		timeout = 0;
		
		//Loop while not finished
		while(finished != true) {
			
			//Add to timeout
			timeout++;
			
			//Sleep the thread for stability
			try { Thread.sleep(5); }
	    	catch (InterruptedException e) { e.printStackTrace(); }
			
			//Check if there is a new message from client
			if(commLink.newMessage()) {
				
				//Read the new message
				String newMessage = commLink.receive();
				
				String decodedMessage = "";
				
				//Decode message
				if(RSAActive) { //Decode with RSA
					decodedMessage = lib.RSAStringDecode(newMessage);
					System.out.println("Client --> Server (RSA): "+decodedMessage);
				}else if(AESActive){	//Decode with AES
					decodedMessage = dataExchangeDecrypt(newMessage);
					System.out.println("Client --> Server (AES): "+decodedMessage);
				}
				
				//Sleep the thread for stability
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
						
						//READ-ME
						//I had an issue with my RSA Decoding that would not let me decode string messages over 128bits
						//So I had the client call that it was going to send public vars over an integer message
						//The server needs to send an ACK to acknowledge that its ready for the integer messages
						
						//I believe the issue was caused by the way i converted bigIntegers to strings as it had a limit
						
						//Verify RSA Connection
						if(decodedMessage.contains("Client_DH_Public_Vars:Sending")) {
							
							sendACK();
							//Wait for the variables to be sent
							while(true) {
								
								try { Thread.sleep(2); }
						    	catch (InterruptedException e) { e.printStackTrace(); }
								//Wait for new message
								if(commLink.newMessage()) {
									//Decode new message to BigInteger
									BigInteger variables = lib.RSAIntDecode(commLink.receive());
									
									try { Thread.sleep(5); }
							    	catch (InterruptedException e) { e.printStackTrace(); }
									
									//Set values
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
							
							//Generate DiffieHellman Private Variable
							Random rand = new SecureRandom();
							do {  //Make sure that the A is smaller then P
							    DHa = new BigInteger(DHp.toString().length(), rand);
							} while (DHa.compareTo(DHp) >= 0);
							
							//--Transmit Step 5 Server Key
							send("Server_DH_Public_Key:" + lib.DiffieHellmanKey(DHg, DHa, DHp).toString());
						}else {
							System.out.println("Server: UNAUTHORISED ATTEMPT");
							commLink.transmit("ERROR");
							finished = true;
						}

					//--Receive Step 5 Client Key
					}else if(DHb == null) {
						if(decodedMessage.contains("Client_DH_Public_Key:Sending")) {
							
							//READ-ME
							//Explanation for this mess in line 168
							
							sendACK();
							//Wait for the variables to be sent
							while(true) {
								try { Thread.sleep(1); }
						    	catch (InterruptedException e) { e.printStackTrace(); }
								if(commLink.newMessage()) {
									//Decode message to BigInteger
									BigInteger variables = lib.RSAIntDecode(commLink.receive());
									
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
						//AES Connection Secured!
						
						//Verify DiffieHellman Key by using it in Encrypting with AES
						if(decodedMessage.contains("Client_DH_Verify")) {
							DHVerified = true;
							//Send DiffieHellman Verification to Client
							send(dataExchangeEncrypt(lib.convertToBigInt("Server_DH_Verify")));
						}else {
							System.out.println("Server: DH Key Not Correct!");
							finished = true;
						}
						
					}else {
						//Exchange 64 Bytes Message
						send(dataExchangeEncrypt(lib.convertToBigInt("Nobody uses Internet Explorer, except to download Chrome/Firefox")));
					}
				}
			}
			
			//Check if timeout occurs
			if(timeout > TTL) {
				System.out.println("Server: TIMEOUT");
				break;
			}
		}
		finished = true;
		System.out.println("Server: STOPPED");
		commLink.closeConnections();
	}
	
	//Delay message before sending for stability
	private void send(String message) {
		try { Thread.sleep(2); }
    	catch (InterruptedException e) { e.printStackTrace(); }
		commLink.transmit(message);
		try { Thread.sleep(2); }
		catch (InterruptedException e) { e.printStackTrace(); }
	}
	
	private void sendACK() {
		send("Server_ACK");
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
