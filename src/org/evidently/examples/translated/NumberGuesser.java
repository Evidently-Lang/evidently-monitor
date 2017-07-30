package org.evidently.examples.translated;

import org.evidently.policy.PolicyElementType;
import org.reflections.Reflections;
import org.reflections.scanners.MethodAnnotationsScanner;
import org.reflections.scanners.SubTypesScanner;
import org.reflections.scanners.TypeAnnotationsScanner;
import org.reflections.util.ClasspathHelper;
import org.reflections.util.ConfigurationBuilder;

import java.lang.annotation.Annotation;
import java.lang.reflect.Method;
import java.util.Set;

import org.evidently.annotation.Policy;
import org.evidently.annotations.ReleasePolicyFor;
import org.evidently.annotations.Sink;
import org.evidently.annotations.Source;
import org.evidently.monitor.Label;
import org.evidently.monitor.SecurityLabelManager;

import edu.columbia.cs.psl.phosphor.runtime.MultiTainter;
import edu.columbia.cs.psl.phosphor.runtime.Taint;

public class NumberGuesser {

	private int realNumber = 2600;
	public boolean admin   = false;

	public NumberGuesser() {
		realNumber =  SecurityLabelManager.update(
				realNumber, 
				new Label(
						new String[] { "DB" },        // sinks 
						new String[] { "DB" },         // sources
						PolicyElementType.FLOWPOINT,  // the policy element this matches.
						"Guess.guess"                 // the NAME in the policy it matches. 

				), null);

		admin =  SecurityLabelManager.update(
				admin, 
				new Label(
						new String[] { "DB" },        // sinks 
						new String[] { "DB" },        // sources
						PolicyElementType.FLOWPOINT,  // the policy element this matches.
						"Guess.adminMode"),            // the NAME in the policy it matches. 
				null);

	}

	public boolean checkPassword(@Sink({"DB", "LOG"}) @Source({ "UI" }) int guess) {

		boolean isOK = false;
		
		// : conditional icf error
		if (guess == realNumber) { 
			isOK = true;
		}

		writeLog(guess);       // OK
		
		// HERE we need to check this.
		
		if(admin){
			writeLog(realNumber);  // not OK
		}

		return isOK;
	}

	public void writeLog(@Sink({"LOG"}) int msg) {
		System.out.println("" + msg);
	}
	
	public void writeLog(@Sink("LOG") String msg) {
		System.out.println(msg);
	}
	
	@Sink({"DB"}) @Source({ "DB" })
	public static int getPasswordGuess()
	{
		return 0;
	}

	public static void main(String args[]) {

		int guess = 2600;
	
		guess = SecurityLabelManager.update(guess, new Label(new String[] { "DB", "LOG" }, new String[] { "UI" }), null);
						
		NumberGuesser checker = new NumberGuesser();

		SecurityLabelManager.update(checker, new Label(new String[] { "LITERAL" }, new String[] { "LITERAL" }), null);

		boolean isOK = checker.checkPassword(guess);
		
		if (isOK) {
			checker.writeLog("Login OK");
		} else {
			checker.writeLog("Invalid Username or Password");
		}
		
		

	//	assert( guess == 2600);
		
		//NumberGuesser checker = new NumberGuesser();
		
		//SecurityLabelManager.register(checker, new Label(new String[] { "LITERAL" }, new String[] { "LITERAL" }));
		
		///int g = getPasswordGuess();
		
		//checker.writeLog(g);
	}
		

}
