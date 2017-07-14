package org.evidently.examples.translated;

import org.evidently.annotations.Sink;
import org.evidently.annotations.Source;
import org.evidently.monitor.Label;
import org.evidently.monitor.SecurityLabelManager;

import edu.columbia.cs.psl.phosphor.runtime.MultiTainter;
import edu.columbia.cs.psl.phosphor.runtime.Taint;

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

	private String realPassword = "secret";
	
	public PasswordChecker(){
		SecurityLabelManager.register(realPassword, new Label(new String[]{"DB"}, new String[]{"DB"}));
	}
	
	public boolean checkPassword(@Sink("DB") @Source({"UI"}) String password) {
		
		//: conditional icf error
		if(realPassword.equalsIgnoreCase(password)) { // can't check this for now. 
			return true;
		}
		
		//: error because LOG is not in sinks of password
		writeLog(realPassword);
		
		return false;		
	}
	
	public void writeLog(@Sink("LOG") String msg) {
		System.out.println(msg);
	}
	
	public static void main(String args[]) {
				
		String password = "password";
		
		// for an object
		SecurityLabelManager.register(password, 				
					new Label(new String[]{"DB"}, new String[]{"UI"})				
				);
		
		//: no check
		PasswordChecker checker = new PasswordChecker();
		SecurityLabelManager.register(checker, new Label(new String[]{"LITERAL"}, new String[]{"LITERAL"}));
		
		//: check sinks(password) >= sinks(formal) -- won't go to any more places
		//: check sources(password) <= sources(formal) - won't be tainted by less places
		checker.checkPassword(password);
		
	}
	
	
	
}
