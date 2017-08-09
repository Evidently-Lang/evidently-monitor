package org.evidently.monitor.aspects;

import org.aspectj.lang.JoinPoint;

public class AspectConfig {

	enum MonitorMode {
		WARN, ENFORCE
	}

	private static boolean ready = true;
	
	synchronized public static void setReady(boolean ready){
		AspectConfig.ready = ready;
	}
	
	public static boolean isReady(){
		return AspectConfig.ready;
	}

	public static AspectConfig.MonitorMode enforcementMode = AspectConfig.MonitorMode.WARN;

	public static void reportViolation(JoinPoint jp, String message) {
		reportViolation(jp.toLongString(), message);
	}

	public static void log(JoinPoint jp, String message) {
		log(jp.toLongString(), message);
	}

	public static void traceReturn(JoinPoint jp) {	
		traceReturn(jp.toLongString() + "\n\tLoc=" + jp.getSourceLocation());
	}

	public static void traceCall(JoinPoint jp) {
		traceCall(jp.toLongString() + "\n\tLoc=" + jp.getSourceLocation());
	}
	
	//
	
	public static void reportViolation(String jp, String message) {
		
		System.out.println(
				String.format("[Evidently] [☠️☠️IFC VIOLATION☠☠️️] \n\tDesc=%s\n\tMessage=%s", jp, message));
	
		if (enforcementMode == MonitorMode.ENFORCE) {
			// exit!
			System.exit(-1);
		}
	}

	public static void log(String jp, String message) {
	
		System.out.println(String.format("[Evidently] [TRACE] \n\tDesc=%s\n\tMessage=%s", jp, message));
	}

	public static void traceReturn(String jp) {
	
		System.out.println(String.format("[Evidently] [TRACE] [RETURN] \n\tDesc=%s", jp));
	} 

	public static void traceCall(String jp) {
	
		System.out.println(String.format("[Evidently] [TRACE] [CALL]\n\tDesc=%s", jp));
	}

	public static void traceAssign(JoinPoint jp) {
		System.out.println(String.format("[Evidently] [TRACE] [ASSIGN]\n\tDesc=%s", jp));		
	}

}
