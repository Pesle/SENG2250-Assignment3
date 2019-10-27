import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Random;

public class Server implements Runnable{
		
	private Connection commLink;
	private int serverID;
	private int sessionID;
	private boolean finished;
	
	private boolean setupFinished = false;

	BigInteger p;
	BigInteger q;
	
	Server(int serverID, int sessionID, Connection commLink){
		this.serverID = serverID;
		this.sessionID = sessionID;
		this.commLink = commLink;
		this.finished = false;
		Random rand = new SecureRandom();
		p = BigInteger.probablePrime(2048 / 2, rand);
		q = BigInteger.probablePrime(2048 / 2, rand);
	}
	
	void SetupRequest(String message){
		
	}

	@Override
	public void run() {
		while(finished != true) {
			if(commLink.newMessageFromClient()) {
				String newMessage = commLink.receiveFromClient();
				if(!setupFinished) {
					if(newMessage.contains("Setup_Request:")) {
						setupFinished = true;
						commLink.transmitToClient("Setup:"+RSAPublicKey());
					}				
				}else {
					System.out.println(RSADecode(new BigInteger(newMessage)));
					finished = true;
				}
			}
			try { Thread.sleep(10); }
	    	catch (InterruptedException e) { e.printStackTrace(); }
		}
	}
	
	
	private String RSAPublicKey() {
		String result = "";
		BigInteger n = p.multiply(q);
		BigInteger e = new BigInteger("65537");
		result = ","+ n.toString()+","+e.toString();
		return result;
	}
	
	private String RSADecode(BigInteger input) {
		BigInteger n = p.multiply(q);
		BigInteger m = (p.subtract(BigInteger.ONE)).multiply(q.subtract(BigInteger.ONE));
		BigInteger e = new BigInteger("65537");
		BigInteger d = e.modInverse(m);
		BigInteger result = input.modPow(d, n);
		//byte[] array = result.toByteArray();
		//String message = new String(array, StandardCharsets.US_ASCII);
		String message = result.toString();
		return message;
	}
	
}
