package org.evidently.monitor;

import edu.columbia.cs.psl.phosphor.runtime.DerivedTaintListener;
import edu.columbia.cs.psl.phosphor.runtime.Taint;

public class TaintStoreMergeTracker implements DerivedTaintListener{

	@Override
	public void singleDepCreated(Taint in, Taint out) {
		if(1==1){
			System.out.println("test");
		}
		
	}

	@Override
	public void doubleDepCreated(Taint in1, Taint in2, Taint out) {

		if(1==1){
			System.out.println("test");
		}
		
	}

}
