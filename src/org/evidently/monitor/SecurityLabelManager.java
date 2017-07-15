package org.evidently.monitor;


import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import edu.columbia.cs.psl.phosphor.runtime.MultiTainter;
import edu.columbia.cs.psl.phosphor.runtime.Taint;
import edu.columbia.cs.psl.phosphor.struct.LinkedList.Node;

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
		 
		Taint t = getTaint(o);		 
		 
		 if(t==null){
			 return false;
		 }
		 
		 return true;
	}
	
	public Taint<Label> getTaint(Object o)
	{
		Taint<Label> t = MultiTainter.getTaint(o);
		
		if(t!=null){
			return t;
		}

		// autoboxing
		if(o instanceof Integer){
			t = MultiTainter.getTaint(((Integer)o).intValue());
		}else if(o instanceof Boolean){
			t = MultiTainter.getTaint(((Boolean)o).booleanValue());			
		}else if(o instanceof Float){
			t = MultiTainter.getTaint(((Float)o).floatValue());			
		}else if(o instanceof Double){
			t = MultiTainter.getTaint(((Double)o).doubleValue());			
		}else if(o instanceof Byte){
			t = MultiTainter.getTaint(((Byte)o).byteValue());			
		}else if(o instanceof Long){
			t = MultiTainter.getTaint(((Long)o).longValue());			
		}
		
		
		return t;
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
	
	private static CheckResult checkPair(Label formal, Taint<Label> actual){
		
		// our check takes place in two forms 
		
		// first, we check that everything in DEPS is a valid step in a 
		// information flow lattice. 
		
		// while we do this, we compute the current EFFECTIVE label
		Label effectiveLabel = actual.getLabel();
		
		if(actual.getDependencies()!=null && actual.getDependencies().getFirst()!=null){
			
			for(Node<Label> n = actual.getDependencies().getFirst(); n.next!=null; n=n.next){
				
				Label l = n.entry;
				
				if(effectiveLabel==null){
					effectiveLabel = l;
					continue;
				}
				
				if(Label.isValidDenningFlow(effectiveLabel, l))
				{
					// merge this two labels. 
					Label.mergeSinks(effectiveLabel, l);
					Label.mergeSource(effectiveLabel, l);					
				}
				else if(false){
					
					//TODO label upgrading
				
				} else{
					return new CheckResult(effectiveLabel, l);
				}
			}			
		}		
		
		// update the taint label
		actual.lbl = effectiveLabel;
		{
			System.out.println(String.format("\t[PreFlow] From=%s,To=%s", effectiveLabel.toString(), formal.toString()));
		}
		
		
		// OK, now check this in relation to the formal parameters 
		if(Label.isValidDenningFlow(actual.lbl, formal)){
			// merge
			Label.mergeSinks(actual.lbl, formal);
			Label.mergeSource(actual.lbl, formal);					

		}else if(false){
			// upgrading
		}else{
			return new CheckResult(actual.lbl, formal);
		}
		
		{
			System.out.println(String.format("\t[PostFlow] Final Label=%s", actual.lbl.toString()));
		}
		
		
		return CheckResult.instanceOk();
	}

	public static CheckResult checkMethodCall(List<Label> formalLabels, List<Taint<Label>> actualTaints) {
		
		// check each pair.
		if(formalLabels.size() != actualTaints.size()){
			System.out.println("[MONITOR] System Integrity Violation. Mismatch in Formals / Actuals Arity");
			System.exit(1);
		}
		
		for(int i=0; i<formalLabels.size(); i++){
			CheckResult r = checkPair(formalLabels.get(i), actualTaints.get(i));
			
			if(!r.ok()){
				return r;
			}
		}
		
		return CheckResult.instanceOk();
	}

}
