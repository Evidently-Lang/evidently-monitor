package org.evidently.monitor;


import java.util.ArrayList;
import java.util.List;

import edu.columbia.cs.psl.phosphor.runtime.MultiTainter;
import edu.columbia.cs.psl.phosphor.runtime.Taint;

public class SecurityLabelManager {
			
	public static SecurityLabelManager instance;
	
	public static SecurityLabelManager getInstance() {
		if(instance==null) {
			instance = new SecurityLabelManager();
		}
		
		return instance;
	}
	
	public static Label defaultLabel(){
		return new Label(defaultSinks(), defaultSources());
	}
	
	public static String[] defaultSinks(){
		return new String[]{"ANY"};
	}
	
	public static String[] defaultSources(){
		return new String[]{"ANY"};
	}

	public boolean inCache(Object o) {
		 Taint t = MultiTainter.getTaint(o);
		 if(t==null){
			 return false;
		 }
		 return true;
	}
	
	
	public void registerIfNotRegistered(Object o, Label l) {
		
		int x = 3;
		
		boolean b = inCache(x);
		
		if(inCache(o)) {
			return;
		}		
		
		//if()
		
	}
	public static void register(Object o, Label l) {
		if(getInstance().inCache(o)) {
			return;
		}	

        MultiTainter.taintedObject(o, new Taint<Label>(l));
	}

	// primative types
	public static short register(short o, Label l) {
		if(getInstance().inCache(o)) {
			return o;
		}	

		return MultiTainter.taintedShort(o, l);
	}
	public static int register(int o, Label l) {
		if(getInstance().inCache(o)) {
			return o;
		}	

		return MultiTainter.taintedInt(o, l);
	}
	
	public static long register(long o, Label l) {
		if(getInstance().inCache(o)) {
			return o;
		}	

		return MultiTainter.taintedLong(o, l);
	}
	
	public static double register(double o, Label l) {
		if(getInstance().inCache(o)) {
			return o;
		}	

		return MultiTainter.taintedDouble(o, l);

	}
	
	public static float register(float o, Label l) {
		if(getInstance().inCache(o)) {
			return o;
		}	

		return MultiTainter.taintedFloat(o, l);
	}
	
	public static byte register(byte o, Label l) {
		if(getInstance().inCache(o)) {
			return o;
		}	

		return MultiTainter.taintedByte(o, l);
	}
	
	public static char register(char o, Label l) {
		if(getInstance().inCache(o)) {
			return o;
		}	

		return MultiTainter.taintedChar(o, l);
	}
	
	public static boolean register(boolean o, Label l) {
		if(getInstance().inCache(o)) {
			return o;
		}	

		return MultiTainter.taintedBoolean(o, l);

	}
	
	// array types
	public static short[] register(short[] o, Label l) {
		if(getInstance().inCache(o)) {
			return o;
		}	

		return MultiTainter.taintedShortArray(o, l);
	}
	public static int[] register(int[] o, Label l) {
		if(getInstance().inCache(o)) {
			return o;
		}	

		return MultiTainter.taintedIntArray(o, l);
	}
	
	public static long[] register(long[] o, Label l) {
		if(getInstance().inCache(o)) {
			return o;
		}	

		return MultiTainter.taintedLongArray(o, l);
	}
	
	public static double[] register(double[] o, Label l) {
		if(getInstance().inCache(o)) {
			return o;
		}	

		return MultiTainter.taintedDoubleArray(o, l);

	}
	
	public static float[] register(float[] o, Label l) {
		if(getInstance().inCache(o)) {
			return o;
		}	

		return MultiTainter.taintedFloatArray(o, l);
	}
	
	public static byte[] register(byte[] o, Label l) {
		if(getInstance().inCache(o)) {
			return o;
		}	

		return MultiTainter.taintedByteArray(o, l);
	}
	
	public static char[] register(char[] o, Label l) {
		if(getInstance().inCache(o)) {
			return o;
		}	

		return MultiTainter.taintedCharArray(o, l);
	}
	
	public static boolean[] register(boolean[] o, Label l) {
		if(getInstance().inCache(o)) {
			return o;
		}	

		return MultiTainter.taintedBooleanArray(o, l);

	}

	public static CheckResult checkMethodCall(List<Label> formalLabels, List<Taint<Label>> actualTaints) {
		return null;
	}

}
