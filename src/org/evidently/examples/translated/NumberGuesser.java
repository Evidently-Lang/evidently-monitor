package org.evidently.examples.translated;

import org.evidently.annotations.Sink;
import org.evidently.annotations.Source;
import org.evidently.monitor.Label;
import org.evidently.monitor.SecurityLabelManager;

import edu.columbia.cs.psl.phosphor.runtime.MultiTainter;
import edu.columbia.cs.psl.phosphor.runtime.Taint;

public class NumberGuesser {

	private int realNumber = 2600;

	public NumberGuesser() {
		realNumber = SecurityLabelManager.register(realNumber, new Label(new String[] { "DB" }, new String[] { "DB" }));

	}

	public boolean checkPassword(@Sink({"DB", "LOG"}) @Source({ "UI" }) int guess) {

		boolean isOK = false;
		
		// : conditional icf error
		if (guess == realNumber) { 
			isOK = true;
		}

		writeLog(guess);       // OK
		writeLog(realNumber);  // not OK

		return isOK;
	}

	public void writeLog(@Sink({"LOG"}) int msg) {
		System.out.println("" + msg);
	}
	
	public void writeLog(@Sink("LOG") String msg) {
		System.out.println(msg);
	}

	public static void main(String args[]) {

		int guess = 2600;

		guess = SecurityLabelManager.register(guess, new Label(new String[] { "DB", "LOG" }, new String[] { "UI" }));
				
		NumberGuesser checker = new NumberGuesser();

		SecurityLabelManager.register(checker, new Label(new String[] { "LITERAL" }, new String[] { "LITERAL" }));

		boolean isOK = checker.checkPassword(guess);
		
		if (isOK) {
			checker.writeLog("Login OK");
		} else {
			checker.writeLog("Invalid Username or Password");
		}
	}

}
