package org.evidently.examples;

import org.evidently.annotations.Sink;
import org.evidently.annotations.Source;

public class PasswordChecker {
	
	/**
	 * Base policy:
	 * 
	 * Channels: DB, UI, LOG
	 * 
	 * FLOWS:
	 * 
	 * >>>> UI -> DB, LOG
	 * 
	 */

	private @Source("DB") @Sink("DB") String realPassword = "secret";
	
	public boolean checkPassword(@Sink("DB") @Source({"UI"}) String password, @Sink("NONE") @Source({"NONE"}) String foo) {
		
		//: conditional icf error
		if(realPassword.equalsIgnoreCase(password)) {
			return true;
		}
		
		//: error because LOG is not in sinks of password
		writeLog(realPassword);
		
		return false;		
	}
	
	public void writeLog(@Sink("LOG") @Source({"UI"}) String msg) {
		System.out.println(msg);
	}
	
	public static void main(String args[]) {
				
		//: label this
		@Sink("DB") @Source("UI") String password = "password";
		
		//: no check
		@Sink("LITERAL") @Source("LITERAL") PasswordChecker checker = new PasswordChecker();
		
		//: check sinks(password) >= sinks(formal) -- won't go to any more places
		//: check sources(password) <= sources(formal) - won't be tainted by less places
		checker.checkPassword(password, "a");
		
	}
	
	
	
}
