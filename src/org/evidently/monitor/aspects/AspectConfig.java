package org.evidently.monitor.aspects;

public class AspectConfig {

	private static boolean ready = true;
	
	synchronized public static void setReady(boolean ready){
		AspectConfig.ready = ready;
	}
	
	public static boolean isReady(){
		return AspectConfig.ready;
	}
}
