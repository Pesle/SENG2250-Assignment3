/*
 *  ----C3282137----
 *  Ryan Jobse
 *  SENG2250 S2 2019
 *  Assignment 3
 *  
 *  EncryptionLibrary.java
 *  Has encryption and decryption functions
 *  That are used by the server and client
 */

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

public class EncryptionLibrary {
	
	//Variables for RSA
	private BigInteger RSAn;
	private BigInteger RSAm;
	private BigInteger RSAe;
	private BigInteger RSAd;
	
	//Variables for the DiffieHellman Key
	private BigInteger DHp;
	private BigInteger DHb;
	private BigInteger DHa;
	
	//Salt for AES Encrypting
	private BigInteger salt;
	
	EncryptionLibrary(){
		//Random static value for salt
		//Does not matter as its not in the assignment specs
		//Basically a static value to ignore it
		salt = new BigInteger("654684321312846");
	}
	
	
//	    _____ _______ _____  
//	   / ____|__   __|  __ \ 
//	  | |       | |  | |__) |
//	  | |       | |  |  _  / 
//	  | |____   | |  | | \ \ 
//	   \_____|  |_|  |_|  \_\
	
	public BigInteger CTREncrypt(BigInteger input, BigInteger CTR) {
		//Get Cipher
		BigInteger cipher = new BigInteger(AESEncrypt(CTR));
		//Run XOR method
		BigInteger value = input.xor(cipher);
		return value;
	}
	
	public BigInteger CTRDecrypt(BigInteger input, BigInteger CTR) {
		//Run CBC method
		BigInteger cipher = new BigInteger(AESEncrypt(CTR));
		//Run XOR Method
		BigInteger value = cipher.xor(input);
		return value;
	}
	
	
//	    _____ ____   _____      __  __          _____ 
//	   / ____|  _ \ / ____|    |  \/  |   /\   / ____|
//	  | |    | |_) | |   ______| \  / |  /  \ | |     
//	  | |    |  _ <| |  |______| |\/| | / /\ \| |     
//	  | |____| |_) | |____     | |  | |/ ____ \ |____ 
//	   \_____|____/ \_____|    |_|  |_/_/    \_\_____|
	
	public BigInteger CBCEncrypt(BigInteger val1, BigInteger val2) {
		//Run CBC method
		BigInteger value = val1.xor(val2);
		return value;
	}
	
	public BigInteger CBCDecrypt(BigInteger val1, BigInteger input) {
		//Run CBC method
		BigInteger value = val1.xor(input);
		return value;
	}
	
	
//	            ______  _____ 
//	      /\   |  ____|/ ____|
//	     /  \  | |__  | (___  
//	    / /\ \ |  __|  \___ \ 
//	   / ____ \| |____ ____) |
//	  /_/    \_\______|_____/ 
                          
	public byte[] AESEncrypt(BigInteger input) {
		byte[] output = null;
		try {
			//Conditions for hashing with SHA256
			SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
			//Set salt static value as it isnt specified in assignment specs
			//Set secret key size to 128 as 256 doesnt work
			//Use diffiehellman key as secret key
			PBEKeySpec spec = new PBEKeySpec(DiffieHellmanSecretKey(), salt.toByteArray(), 65556, 128);
			
			//Generate Secret Key
			SecretKey secretKey = factory.generateSecret(spec);
	        SecretKeySpec skeySpec = new SecretKeySpec(secretKey.getEncoded(), "AES");
	 
	        //Use secret key to initialise encryption
	        //Generate AES cipher using ECB (no CBC) and No Padding
	        Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
	        cipher.init(Cipher.ENCRYPT_MODE, skeySpec);
	        
	        //Encrypt the message
	        output = cipher.doFinal(input.toByteArray());
	        
	    } catch (Exception ex) {
	        ex.printStackTrace();
	    }
		return output;
	}
	
	public byte[] AESDecrypt(BigInteger input) {
		byte[] output = null;
		try {
			//Conditions for hashing with SHA256
			SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
			//Set salt static value as it isnt specified in assignment specs
			//Set secret key size to 128 as 256 doesnt work
			//Use diffiehellman key as secret key
			PBEKeySpec spec = new PBEKeySpec(DiffieHellmanSecretKey(), salt.toByteArray(), 65556, 128);
			
			//Generate Secret Key
			SecretKey secretKey = factory.generateSecret(spec);
	        SecretKeySpec skeySpec = new SecretKeySpec(secretKey.getEncoded(), "AES");
	 
	        //Use secret key to initialise decryption
	        //Generate AES cipher using ECB (no CBC) and No Padding
	        Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
	        cipher.init(Cipher.DECRYPT_MODE, skeySpec);
	        
	        //Decrypt the message
	        output = cipher.doFinal(input.toByteArray());
	        
	    } catch (Exception ex) {
	        ex.printStackTrace();
	    }
		return output;
	}
	
	
//	   _____  _  __  __ _             _    _      _ _                       
//	  |  __ \(_)/ _|/ _(_)           | |  | |    | | |                      
//	  | |  | |_| |_| |_ _  ___ ______| |__| | ___| | |_ __ ___   __ _ _ __  
//	  | |  | | |  _|  _| |/ _ \______|  __  |/ _ \ | | '_ ` _ \ / _` | '_ \ 
//	  | |__| | | | | | | |  __/      | |  | |  __/ | | | | | | | (_| | | | |
//	  |_____/|_|_| |_| |_|\___|      |_|  |_|\___|_|_|_| |_| |_|\__,_|_| |_|
	
	public BigInteger DiffieHellmanKey(BigInteger g, BigInteger a, BigInteger p) {
		this.DHa = a;
		this.DHp = p;
		//Return public diffieHellman key 
		return g.modPow(a, p);
	}
	
	public char[] DiffieHellmanSecretKey() {
		//Get private key
		String key = DHb.modPow(DHa, DHp).toString();		
		return key.toCharArray();
	}
	
	public void setDiffieHellmanB(BigInteger b) {
		//Set other public key
		this.DHb = b;
	}
	
	
//	    _____                              _                 
//	   / ____|                            (_)                
//	  | |     ___  _ ____   _____ _ __ ___ _  ___  _ __  ___ 
//	  | |    / _ \| '_ \ \ / / _ \ '__/ __| |/ _ \| '_ \/ __|
//	  | |___| (_) | | | \ V /  __/ |  \__ \ | (_) | | | \__ \
//	   \_____\___/|_| |_|\_/ \___|_|  |___/_|\___/|_| |_|___/
	
	public String convertFromBigInt(BigInteger input) {
		//Convert BigInteger to bytes
		byte[] array = input.toByteArray();
		//Convert bytes to UTF-8 String
		String message = new String(array, StandardCharsets.UTF_8);
		return message;
	}
	
	public BigInteger convertToBigInt(String input) {
		BigInteger message = null;
		try {
			//Try to convert String to bytes then to a BigInteger
			message = new BigInteger(input.getBytes("UTF-8"));
		} catch (Exception e){
			e.printStackTrace();
		}
		return message;
	}
	
	
//	   _____   _____         
//	  |  __ \ / ____|  /\    
//	  | |__) | (___   /  \   
//	  |  _  / \___ \ / /\ \  
//	  | | \ \ ____) / ____ \ 
//	  |_|  \_\_____/_/    \_\
	
	public String RSAPublicKey(BigInteger p, BigInteger q) {
		String result = "";
		
		//RSA Steps
		RSAn = p.multiply(q);
		RSAe = new BigInteger("65537");
		RSAm = (p.subtract(BigInteger.ONE)).multiply(q.subtract(BigInteger.ONE));
		RSAd = RSAe.modInverse(RSAm);
		
		//Return RSA Public variables
		result = RSAn.toString()+","+RSAe.toString();
		return result;
	}
	
	public String RSAStringDecode(String input) {		
		//Convert Input String to Big Integer
		BigInteger in = new BigInteger(input);
		
		//Decode the RSA with private keys
		BigInteger result = in.modPow(RSAd, RSAn);
		
		//Return a converted bigInt to string
		return convertFromBigInt(result);
	}
	
	public BigInteger RSAIntDecode(String input) {		
		//Convert Input String to Big Integer
		BigInteger in = new BigInteger(input);
		
		//Decode the RSA with private keys
		BigInteger result = in.modPow(RSAd, RSAn);
		
		//Return bigInt
		return result;
	}
	
	public void setRSAPublicVars(BigInteger n, BigInteger e) {
		//Set RSA public variables
		RSAn = n;
		RSAe = e;
	}
	
	public String RSAStringEncode(String input) {
		BigInteger message = convertToBigInt(input);
		//Try to change the input from UTF-8 to bytes which converts to bigIntegers
		
		//Encode the message with the public key
		return message.modPow(RSAe, RSAn).toString();
	}
	
	public String RSAIntEncode(BigInteger input) {
		//Try to change the input from UTF-8 to bytes which converts to bigIntegers
		
		//Encode the message with the public key
		return input.modPow(RSAe, RSAn).toString();
	}
	
}
