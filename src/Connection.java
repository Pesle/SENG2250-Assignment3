/*
 *  ----C3282137----
 *  Ryan Jobse
 *  SENG2250 S2 2019
 *  Assignment 3
 *  
 *  Connection.java
 *  Manages the connections that are used
 *  by the server and the client
 */

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.ServerSocket;
import java.net.Socket;

public class Connection {
	
	private ServerSocket sSocket = null;
	private Socket socket = null;
    private InputStreamReader  input = null; 
    private BufferedReader bfInput = null;
    private PrintWriter output = null;
    
    private String previousError = "";
	
	public boolean connectClient(String address, int port){
		try
        { 
            socket = new Socket(address, port);  
            input  = new InputStreamReader(socket.getInputStream()); 
            bfInput = new BufferedReader(input);
            
            output = new PrintWriter(socket.getOutputStream()); 
            return true;
        } 
        catch(IOException i) 
        { 
        	String exception = i.toString();
        	if(!exception.equals(previousError)) {
        		System.out.println("Client: " + exception); 
        		previousError = exception;
        	}
            return false;
        } 
	}
	
	public boolean connectServer(int port){
		try
        { 
			sSocket = new ServerSocket(port);
            socket = sSocket.accept(); 
            input  = new InputStreamReader(socket.getInputStream()); 
            bfInput = new BufferedReader(input);
            
            output = new PrintWriter(socket.getOutputStream()); 
            return true;
        } 
        catch(IOException i) 
        { 
        	String exception = i.toString();
        	if(!exception.equals(previousError)) {
        		System.out.println("Server: " + exception); 
        		previousError = exception;
        	}
            return false;
        } 
	}
	
	public void closeConnections() {
		try {
			if(input != null) {
				input.close();
				output.close();
				socket.close();
				if(sSocket != null) {
					sSocket.close();
				}
			}
		} catch (IOException e) {
			e.printStackTrace();
		}
	}
	
	
	public void transmit(String message) {
		output.println(message);
		output.flush();
	}
	
	public String receive() {
		String message = "";
		try {
			message = bfInput.readLine();
		} catch (IOException e) {
			System.out.println(e);
		}
		return message;
	}
	
	public boolean newMessage() {
		boolean result = false;
		try {
			result = bfInput.ready();
		} catch (IOException e) {
			e.printStackTrace();
		}
		return result;
	}
}
