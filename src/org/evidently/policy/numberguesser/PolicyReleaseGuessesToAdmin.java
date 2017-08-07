package org.evidently.policy.numberguesser;

import org.evidently.annotations.Policy;
import org.evidently.annotations.ReleaseParam;
import org.evidently.annotations.ReleasePolicyFor;

@Policy("PolicyReleaseGuessesToAdmin")
public class PolicyReleaseGuessesToAdmin {

	
	@ReleasePolicyFor("Guess.guess")                       // this is the name of the thing we are trying to release
	public  boolean release_1_Guess___guess(
			@ReleaseParam("Guess.guess") int Guess___guess,             // the entire context is made available as command line arguments 
			@ReleaseParam("Guess.adminMode") boolean Guess___adminMode  // and then rewritten in the subexpressions
	) 
	{		
		return release_1_Guess___guess_WHEN(Guess___guess, Guess___adminMode) && !release_1_Guess___guess_UNLESS(Guess___guess,Guess___adminMode);
	}
	
	
	private boolean release_1_Guess___guess_WHEN(
			int p1,         
			boolean p2 
	) 
	{		
		return p2==true;
	}
	
	private boolean release_1_Guess___guess_UNLESS(
			int p1,         
			boolean p2  
	) 
	{		
		return p2==false;
	}

}
