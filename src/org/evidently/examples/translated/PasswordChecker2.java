package org.evidently.examples.translated;

import org.evidently.annotations.Sink;
import org.evidently.annotations.Source;
import org.evidently.monitor.Label;
import org.evidently.monitor.SecurityLabelManager;

import edu.columbia.cs.psl.phosphor.runtime.MultiTainter;
import edu.columbia.cs.psl.phosphor.runtime.Taint;

public class PasswordChecker2 {


	private String realPassword = "secret";

	public PasswordChecker2() {
		MultiTainter.taintedObject(realPassword, new Taint("realPassword"));		
	}

	public int checkPassword(String password) {

		int isOK = 0;
		
		// : implicit flow
		if (realPassword == password) { // can't check this for now.
			isOK = 1;
		}

		Taint t1 = MultiTainter.getTaint(isOK); // isOk is null! 
		Taint t2 = MultiTainter.getTaint(realPassword);
		Taint t3 = MultiTainter.getTaint(password);
		
		return isOK;
	}


	public static void main(String args[]) {

		String password = "secret";
		MultiTainter.taintedObject(password, new Taint("password"));

		PasswordChecker2 checker = new PasswordChecker2();

		int isOK = checker.checkPassword(password);
	}

}
