import java.math.BigInteger;
import java.nio.charset.StandardCharsets;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

public class EncryptionLibrary {
	
	private BigInteger RSAn;
	private BigInteger RSAm;
	private BigInteger RSAe;
	private BigInteger RSAd;
	
	private BigInteger DHp;
	private BigInteger DHb;
	private BigInteger DHa;
	
	
	private BigInteger salt;
	
	EncryptionLibrary(){
		salt = new BigInteger("654684321312846");
	}
	
	
	public BigInteger CTREncrypt(BigInteger input, BigInteger CTR) {
		//Get Cipher
		BigInteger cipher = new BigInteger(AESEncrypt(CTR));
		//Run CBC method
		BigInteger value = input.xor(cipher);
		return value;
	}
	
	public BigInteger CTRDecrypt(BigInteger input, BigInteger CTR) {
		//Run CBC method
		BigInteger cipher = new BigInteger(AESEncrypt(CTR));
		BigInteger value = cipher.xor(input);
		return value;
	}
	
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
	
	public byte[] AESEncrypt(BigInteger input) {
		byte[] output = null;
		try {
			//Conditions for hashing with SHA256
			SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
			//Set salt as CBCInitial vector as its random and known to both parties
			//Set secret key size to 128 as 256 doesnt work
			PBEKeySpec spec = new PBEKeySpec(DiffieHellmanSecretKey(), salt.toByteArray(), 65556, 128);
			
			//Generate Secret Key
			SecretKey secretKey = factory.generateSecret(spec);
	        SecretKeySpec skeySpec = new SecretKeySpec(secretKey.getEncoded(), "AES");
	 
	        //Use secret key to initialise encryption
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
			//Set salt as CBCInitial vector as its random and known to both parties
			//Set secret key size to 128 as 256 doesnt work
			PBEKeySpec spec = new PBEKeySpec(DiffieHellmanSecretKey(), salt.toByteArray(), 65556, 128);
			
			//Generate Secret Key
			SecretKey secretKey = factory.generateSecret(spec);
	        SecretKeySpec skeySpec = new SecretKeySpec(secretKey.getEncoded(), "AES");
	 
	      //Use secret key to initialise decryption
	        Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
	        cipher.init(Cipher.DECRYPT_MODE, skeySpec);
	        
	        //Decrypt the message
	        output = cipher.doFinal(input.toByteArray());
	        
	    } catch (Exception ex) {
	        ex.printStackTrace();
	    }
		return output;
	}
	
	public BigInteger DiffieHellmanKey(BigInteger g, BigInteger a, BigInteger p) {
		this.DHa = a;
		this.DHp = p;
		return g.modPow(a, p);
	}
	
	public char[] DiffieHellmanSecretKey() {
		//Get key
		String key = DHb.modPow(DHa, DHp).toString();		
		return key.toCharArray();
	}
	
	public void setDiffieHellmanB(BigInteger b) {
		this.DHb = b;
	}
	
	public String convertFromBigInt(BigInteger input) {
		//Convert bytes back to UTF-8
		byte[] array = input.toByteArray();
		String message = new String(array, StandardCharsets.UTF_8);
		return message;
	}
	
	public BigInteger convertToBigInt(String input) {
		BigInteger message = null;
		try {
			message = new BigInteger(input.getBytes("UTF-8"));
		} catch (Exception e){
			e.printStackTrace();
		}
		return message;
	}
	
	public String RSAPublicKey(BigInteger p, BigInteger q) {
		String result = "";
		RSAn = p.multiply(q);
		RSAe = new BigInteger("65537");
		RSAm = (p.subtract(BigInteger.ONE)).multiply(q.subtract(BigInteger.ONE));
		RSAd = RSAe.modInverse(RSAm);
		
		result = RSAn.toString()+","+RSAe.toString();
		return result;
	}
	
	public String RSAStringDecode(String input) {		
		//Convert Input String to Big Integer
		BigInteger in = new BigInteger(input);
		
		//Decode the RSA with private keys
		BigInteger result = in.modPow(RSAd, RSAn);
		
		return convertFromBigInt(result);
	}
	
	public BigInteger RSAIntDecode(String input) {		
		//Convert Input String to Big Integer
		BigInteger in = new BigInteger(input);
		
		//Decode the RSA with private keys
		BigInteger result = in.modPow(RSAd, RSAn);
		
		return result;
	}
	
	public void setRSAPublicVars(BigInteger n, BigInteger e) {
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
