package org.evidently.monitor;

import java.lang.annotation.Annotation;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Parameter;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Set;

import org.evidently.annotation.Policy;
import org.evidently.annotations.ReleaseParam;
import org.evidently.annotations.ReleasePolicyFor;
import org.evidently.annotations.Sink;
import org.evidently.annotations.Source;
import org.evidently.labels.defaults.LabelSet;
import org.evidently.monitor.aspects.AspectConfig;
import org.evidently.policy.PolicyElementType;
import org.evidently.policy.numberguesser.PolicyReleaseGuessesToAdmin;
import org.reflections.Reflections;
import org.reflections.scanners.MethodAnnotationsScanner;
import org.reflections.scanners.SubTypesScanner;
import org.reflections.scanners.TypeAnnotationsScanner;
import org.reflections.util.ClasspathHelper;
import org.reflections.util.ConfigurationBuilder;

import edu.columbia.cs.psl.phosphor.runtime.MultiTainter;
import edu.columbia.cs.psl.phosphor.runtime.Taint;
import edu.columbia.cs.psl.phosphor.runtime.Tainter;
import edu.columbia.cs.psl.phosphor.struct.ControlTaintTagStack;
import edu.columbia.cs.psl.phosphor.struct.LinkedList.Node;

public class SecurityLabelManager {

	public static SecurityLabelManager instance;
	private static HashMap<String, Pair<Object, Label>> context = new HashMap<String, Pair<Object, Label>>();
	public LabelSet labelSet;
	
	
	private SecurityLabelManager(){
		try {
			labelSet = (LabelSet)Class.forName("org.evidently.labels.PolicyLabelSet").newInstance();
		} catch (InstantiationException | IllegalAccessException | ClassNotFoundException e) {
			System.out.println("[Evidently] Unable to load policy labels. Using defaults...");			
			labelSet = new LabelSet();
		}
	}
	
	public static SecurityLabelManager getInstance() {
		if (instance == null) {
			instance = new SecurityLabelManager();
		}

		return instance;
	}

	public static Label defaultLabel() {
		return new Label(defaultSinks(), defaultSources());
	}

	public static String[] defaultSinks() {
		return  SecurityLabelManager.getInstance().labelSet.sinks();
	}

	public static String[] defaultSources() {
		return new String[] {};
	}

	public Taint inCache(Object o) {
		return getTaint(o);
	}

	public Taint<Label> getTaint(Object o) {
		Taint<Label> t = MultiTainter.getTaint(o);

		if (t != null) {
			return t;
		}

		// autoboxing
		if (o instanceof Integer) {
			t = MultiTainter.getTaint(((Integer) o).intValue());
		} else if (o instanceof Boolean) {
			t = MultiTainter.getTaint(((Boolean) o).booleanValue());
		} else if (o instanceof Float) {
			t = MultiTainter.getTaint(((Float) o).floatValue());
		} else if (o instanceof Double) {
			t = MultiTainter.getTaint(((Double) o).doubleValue());
		} else if (o instanceof Byte) {
			t = MultiTainter.getTaint(((Byte) o).byteValue());
		} else if (o instanceof Long) {
			t = MultiTainter.getTaint(((Long) o).longValue());
		}

		return t;
	}

	/////////
	// if the label is specified, we ONLY use the label IF it ISN'T in the cache
	///////// already.
	// otherwise we just update the context value.
	public static void update(Object o, Label l, Taint<Label> previousTaint) {

		if (AspectConfig.isReady() == false)
			return;

		Taint<Label> currentTaint = getInstance().inCache(o);
		if (currentTaint != null) {

			if (isSpecial(currentTaint)) {
				updateContexts(currentTaint, o, context);
			}

		} else {
			if (l != null) {
				MultiTainter.taintedObject(o, new Taint<Label>(l));

				if (l.isSpecial()) {
					l.updateContexts(o, context);
				}
			}
		}
	}

	public static short update(short o, Label l, Taint<Label> previousTaint) {

		if (AspectConfig.isReady() == false)
			return o;

		Taint<Label> currentTaint = getInstance().inCache(o);
		if (currentTaint != null) {

			if (isSpecial(currentTaint)) {
				updateContexts(currentTaint, o, context);
			}

			return o;
		} else if (l != null) {
			if (l.isSpecial()) {
				l.updateContexts(o, context);
			}

			return MultiTainter.taintedShort(o, l);
		}

		return o;
	}
	
	private static String getCaller(){
		StackTraceElement e = null;
		
		for(StackTraceElement ele : Thread.currentThread().getStackTrace()){
			if(ele.getClassName().startsWith("org.evidently")||
					ele.getClassName().startsWith("edu.columbia") ||
					ele.getClassName().startsWith("java.lang")
					){
				continue;
			}
				e = ele;
				break;
		}
					
			
		
		
		
		if(e==null){
			return "(can't locate source position)";
		}
		return String.format("%s:%d", e.getFileName(), e.getLineNumber());
	}

	public static int update(int o, Label l, Taint<Label> previousTaint) {

		if (AspectConfig.isReady() == false)
			return o;


		Taint<Label> currentTaint = getInstance().inCache(o);
		
		String a1 = currentTaint != null ? currentTaint.toString() : "(none)";
		String a2 = previousTaint != null ? previousTaint.toString() : "(none)";
		String a3 = l != null ? l.toString() : "(none)";
		
		System.out.println(String.format("[Evidently] Calling update(int): \n\tTaint: %s\n\tPrevious Taint: %s\n\tLabel Arg: %s", a1, a2, a3));
		System.out.println("\tCall Src: UPDATE @ " + getCaller());

		{			
			CheckResult cr = SecurityLabelManager._checkAssignment(previousTaint, currentTaint);
		}
		
		
		
		if (currentTaint != null) {

			System.out.println("[Evidently] IN cache: " + currentTaint);

			if (isSpecial(currentTaint)) {
				updateContexts(currentTaint, o, context);
			}

			return o;
		} else if (l != null) {

			System.out.println("[Evidently] NOT in cache");

			if (l.isSpecial()) {
				l.updateContexts(o, context);
			}

			return MultiTainter.taintedInt(o, l);
		}

		return o;
	}

	public static CheckResult _checkAssignment(Taint<Label> previousTaint, Taint<Label> currentTaint) {
		// NOTE -- this method only exists to capture
		// assignment in the monitor aspect.
		System.out.println("[Evidently] _checkAssignment (noop)"); // to make sure the compiler doesn't optimize this away.
		return null;
	}

	public static long update(long o, Label l, Taint<Label> previousTaint) {

		if (AspectConfig.isReady() == false)
			return o;

		Taint<Label> currentTaint = getInstance().inCache(o);
		if (currentTaint != null) {

			if (isSpecial(currentTaint)) {
				updateContexts(currentTaint, o, context);
			}

			return o;
		} else if (l != null) {
			if (l.isSpecial()) {
				l.updateContexts(o, context);
			}

			return MultiTainter.taintedLong(o, l);
		}

		return o;
	}

	public static double update(double o, Label l, Taint<Label> previousTaint) {

		if (AspectConfig.isReady() == false)
			return o;

		Taint<Label> currentTaint = getInstance().inCache(o);
		if (currentTaint != null) {

			if (isSpecial(currentTaint)) {
				updateContexts(currentTaint, o, context);
			}

			return o;
		} else if (l != null) {
			if (l.isSpecial()) {
				l.updateContexts(o, context);
			}

			return MultiTainter.taintedDouble(o, l);
		}

		return o;
	}

	public static float update(float o, Label l, Taint<Label> previousTaint) {

		if (AspectConfig.isReady() == false)
			return o;

		Taint<Label> currentTaint = getInstance().inCache(o);
		if (currentTaint != null) {

			if (isSpecial(currentTaint)) {
				updateContexts(currentTaint, o, context);
			}

			return o;
		} else if (l != null) {
			if (l.isSpecial()) {
				l.updateContexts(o, context);
			}

			return MultiTainter.taintedFloat(o, l);
		}

		return o;
	}

	public static byte update(byte o, Label l, Taint<Label> previousTaint) {

		if (AspectConfig.isReady() == false)
			return o;

		Taint<Label> currentTaint = getInstance().inCache(o);
		if (currentTaint != null) {

			if (isSpecial(currentTaint)) {
				updateContexts(currentTaint, o, context);
			}

			return o;
		} else if (l != null) {
			if (l.isSpecial()) {
				l.updateContexts(o, context);
			}

			return MultiTainter.taintedByte(o, l);
		}

		return o;
	}

	public static char update(char o, Label l, Taint<Label> previousTaint) {

		if (AspectConfig.isReady() == false)
			return o;

		Taint<Label> currentTaint = getInstance().inCache(o);
		if (currentTaint != null) {

			if (isSpecial(currentTaint)) {
				updateContexts(currentTaint, o, context);
			}

			return o;
		} else if (l != null) {
			if (l.isSpecial()) {
				l.updateContexts(o, context);
			}

			return MultiTainter.taintedChar(o, l);
		}

		return o;
	}

	public static boolean update(boolean o, Label l, Taint<Label> previousTaint) {

		if (AspectConfig.isReady() == false)
			return o;

		Taint<Label> currentTaint = getInstance().inCache(o);
		if (currentTaint != null) {

			if (isSpecial(currentTaint)) {
				updateContexts(currentTaint, o, context);
			}

			return o;
		} else if (l != null) {
			if (l.isSpecial()) {
				l.updateContexts(o, context);
			}

			return MultiTainter.taintedBoolean(o, l);
		}

		return o;
	}

	////////

	public static short[] update(short[] o, Label l, Taint<Label> previousTaint) {

		if (AspectConfig.isReady() == false)
			return o;

		Taint<Label> currentTaint = getInstance().inCache(o);
		if (currentTaint != null) {

			if (isSpecial(currentTaint)) {
				updateContexts(currentTaint, o, context);
			}

			return o;
		} else if (l != null) {
			if (l.isSpecial()) {
				l.updateContexts(o, context);
			}

			return MultiTainter.taintedShortArray(o, l);
		}

		return o;
	}

	public static int[] update(int[] o, Label l, Taint<Label> previousTaint) {

		if (AspectConfig.isReady() == false)
			return o;

		Taint<Label> currentTaint = getInstance().inCache(o);
		if (currentTaint != null) {

			if (isSpecial(currentTaint)) {
				updateContexts(currentTaint, o, context);
			}

			return o;
		} else if (l != null) {
			if (l.isSpecial()) {
				l.updateContexts(o, context);
			}

			return MultiTainter.taintedIntArray(o, l);
		}

		return o;
	}

	public static long[] update(long[] o, Label l, Taint<Label> previousTaint) {

		if (AspectConfig.isReady() == false)
			return o;

		Taint<Label> currentTaint = getInstance().inCache(o);
		if (currentTaint != null) {

			if (isSpecial(currentTaint)) {
				updateContexts(currentTaint, o, context);
			}

			return o;
		} else if (l != null) {
			if (l.isSpecial()) {
				l.updateContexts(o, context);
			}

			return MultiTainter.taintedLongArray(o, l);
		}

		return o;
	}

	public static double[] update(double[] o, Label l, Taint<Label> previousTaint) {

		if (AspectConfig.isReady() == false)
			return o;

		Taint<Label> currentTaint = getInstance().inCache(o);
		if (currentTaint != null) {

			if (isSpecial(currentTaint)) {
				updateContexts(currentTaint, o, context);
			}

			return o;
		} else if (l != null) {
			if (l.isSpecial()) {
				l.updateContexts(o, context);
			}

			return MultiTainter.taintedDoubleArray(o, l);
		}

		return o;
	}

	public static float[] update(float[] o, Label l, Taint<Label> previousTaint) {

		if (AspectConfig.isReady() == false)
			return o;

		Taint<Label> currentTaint = getInstance().inCache(o);
		if (currentTaint != null) {

			if (isSpecial(currentTaint)) {
				updateContexts(currentTaint, o, context);
			}

			return o;
		} else if (l != null) {
			if (l.isSpecial()) {
				l.updateContexts(o, context);
			}

			return MultiTainter.taintedFloatArray(o, l);
		}

		return o;
	}

	public static byte[] update(byte[] o, Label l, Taint<Label> previousTaint) {

		if (AspectConfig.isReady() == false)
			return o;

		Taint<Label> currentTaint = getInstance().inCache(o);
		if (currentTaint != null) {

			if (isSpecial(currentTaint)) {
				updateContexts(currentTaint, o, context);
			}

			return o;
		} else if (l != null) {
			if (l.isSpecial()) {
				l.updateContexts(o, context);
			}

			return MultiTainter.taintedByteArray(o, l);
		}

		return o;
	}

	public static char[] update(char[] o, Label l, Taint<Label> previousTaint) {

		if (AspectConfig.isReady() == false)
			return o;

		Taint<Label> currentTaint = getInstance().inCache(o);
		if (currentTaint != null) {

			if (isSpecial(currentTaint)) {
				updateContexts(currentTaint, o, context);
			}

			return o;
		} else if (l != null) {
			if (l.isSpecial()) {
				l.updateContexts(o, context);
			}

			return MultiTainter.taintedCharArray(o, l);
		}

		return o;
	}

	public static boolean[] update(boolean[] o, Label l, Taint<Label> previousTaint) {

		if (AspectConfig.isReady() == false)
			return o;

		Taint<Label> currentTaint = getInstance().inCache(o);
		if (currentTaint != null) {

			if (isSpecial(currentTaint)) {
				updateContexts(currentTaint, o, context);
			}

			return o;
		} else if (l != null) {
			if (l.isSpecial()) {
				l.updateContexts(o, context);
			}

			return MultiTainter.taintedBooleanArray(o, l);
		}

		return o;
	}

	public static CheckResult checkAssignment(Taint<Label> previousLHSTaint, Taint<Label> rhsTaint) {

		ControlTaintTagStack taintStack = MultiTainter.getControlFlow();
		
		// nothing happened
//		if(rhsTaint.lbl.sameFlow(previousLHSTaint.lbl)){
//			return CheckResult.instanceOk();
//		}
		
		
		// information flow lattice.
		CheckResult conversionResult = taintToLabel(previousLHSTaint);

		// we can't convert it because an invalid flow has 
		// happened previously (or implicitly!)
		if (conversionResult.ok() == false) {
			return conversionResult;
		}
		
		//
		// actually check it.
		//
		return checkPair(conversionResult.getRes(), rhsTaint);
	}
	
	private static boolean noControlFlow(ControlTaintTagStack taintStack){
		if(taintStack==null 
				|| taintStack.getTag()==null 
				|| 
		(taintStack.getTag().getLabel()==null && (taintStack.getTag().getDependencies()==null || taintStack.getTag().getDependencies().getFirst()==null))){
			return true;
		}
		
		return false;
	}

	/////
	private static CheckResult taintToLabel(Taint<Label> actual) {

		// our check takes place in two forms

		// first, we check that everything in DEPS is a valid step in a
		// information flow lattice.

		// while we do this, we compute the current EFFECTIVE label
		Label effectiveLabel = actual.getLabel();

		if (effectiveLabel == null && actual.getDependencies() != null && actual.getDependencies().getFirst() != null) {
			effectiveLabel = actual.getDependencies().getFirst().entry;
		}

		if (actual.getDependencies() != null && actual.getDependencies().getFirst() != null) {

			for (Node<Label> n = actual.getDependencies().getFirst(); n.next != null; n = n.next) {

				Label l = n.entry;

				if (effectiveLabel == null) {
					effectiveLabel = l;
					continue;
				}

				if (Label.isValidDenningFlow(effectiveLabel, l)) {
					// merge this two labels.
					Label.mergeSinks(effectiveLabel, l);
					Label.mergeSource(effectiveLabel, l);
				} else if (policyJustifiesUpgrade(effectiveLabel, l)) {

					Label.mergeSinks(effectiveLabel, l);
					Label.mergeSource(effectiveLabel, l);

				} else {
					// IFC ERROR
					return new CheckResult(effectiveLabel, l);
				}
			}
		}

		return CheckResult.instanceOk(effectiveLabel);
	}

	private static CheckResult checkPair(Label formal, Taint<Label> actual) {

		// our check takes place in two forms

		// first, we check that everything in DEPS is a valid step in a
		// information flow lattice.
		CheckResult conversionResult = taintToLabel(actual);

		if (conversionResult.ok() == false) {
			return conversionResult;
		}

		// while we do this, we compute the current EFFECTIVE label
		Label effectiveLabel = conversionResult.getRes();

		// update the taint label
		actual.lbl = effectiveLabel;
		{
			System.out
					.println(String.format("\t[PreFlow] From=%s,To=%s", effectiveLabel.toString(), formal.toString()));
		}

		// OK, now check this in relation to the formal parameters
		if (Label.isValidDenningFlow(actual.lbl, formal)) {
			// merge
			Label.mergeSinks(actual.lbl, formal);
			Label.mergeSource(actual.lbl, formal);

		} else if (policyJustifiesUpgrade(actual.lbl, formal)) {
			// upgrading
			// merge
			Label.mergeSinks(actual.lbl, formal);
			Label.mergeSource(actual.lbl, formal);

		} else {
			return new CheckResult(actual.lbl, formal);
		}

		{
			System.out.println(String.format("\t[PostFlow] Final Label=%s", actual.lbl.toString()));
		}

		return CheckResult.instanceOk();
	}

	private static boolean policyJustifiesUpgrade(Label lbl, Label formal) {

		// find a policy for the given variable that justifies
		// this release.
		System.out.println(String.format("[Evidently] [Policy] Looking for Policies for [%s]", lbl.toString()));

		List<Pair<PolicyElementType, String>> elements = lbl.getPolicyElementTypes();

		if (elements.size() == 0) {
			System.out.println(
					String.format("[Evidently] [Policy] Label does not have any avilable tagged policy elements..."));

			return false; // nothing to justify!
		}

		Reflections reflections = new Reflections(
				new ConfigurationBuilder().setUrls(ClasspathHelper.forPackage("org.evidently.policy")).setScanners(
						new SubTypesScanner(), new TypeAnnotationsScanner(), new MethodAnnotationsScanner()));

		Set<Class<?>> allPolicies = reflections.getTypesAnnotatedWith(Policy.class);

		for (Class c : allPolicies) {
			System.out.println(String.format("[Evidently] [Policy] Loaded Policy: %s", c.getName()));
		}

		System.out.println(
				String.format("[Evidently] [Policy] Looking for Policies that can declassify any of the following: "));

		for (Pair<PolicyElementType, String> element : elements) {
			System.out.println(String.format("\t[%s], Type: %s", element.getRight(), element.getLeft()));
		}

		Set<Method> methods = reflections.getMethodsAnnotatedWith(ReleasePolicyFor.class);

		// see if any of these are true!
		for (Pair<PolicyElementType, String> element : elements) {
			for (Method m : methods) {

				if (fromJavaName(m.getName()).endsWith(element.getRight())) {
					// TODO - first check if the FLOW is ok.
					System.out.println(String.format(
							"[Evidently] [Policy] Checking release policy for [%s], Type: %s, Translated Policy: [%s]",
							element.getRight(), element.getLeft(), m.getName()));

					// build the arguments
					Object[] args = buildArgumentsFromContext(m);
					try {
						Object target = m.getDeclaringClass().newInstance();

						boolean isOK = (boolean) m.invoke(target, args);

						System.out.println(String.format("[Evidently] [Policy] OK?:  %s", isOK));

						if (isOK) {
							return isOK; // first rule to match wins
						}

					} catch (IllegalAccessException | IllegalArgumentException | InvocationTargetException
							| InstantiationException e) {
						System.err.println(
								"[Evidently] [Policy] Error invoking declassification function " + m.getName());
						e.printStackTrace();
					}

				}
			}
		}
		return false;
	}

	
	public static void updateContexts(Taint<Label> t, Object o, HashMap<String, Pair<Object, Label>> context){
		
		if(t.getLabel()!=null){
			t.getLabel().updateContexts(o, context);
		}
		
		if(t.getDependencies()!=null && t.getDependencies().getFirst()!=null){
			for (Node<Label> n = t.getDependencies().getFirst(); n.next != null; n = n.next) {
				if(n.entry!=null){
					n.entry.updateContexts(o, context);
				}
			}
		}
		
		
		
	}
	
	public static boolean isSpecial(Taint<Label> t){
		if(t.getLabel()!=null && t.getLabel().isSpecial()){
			return true;
		}
		
		if(t.getDependencies()!=null && t.getDependencies().getFirst()!=null){
			for (Node<Label> n = t.getDependencies().getFirst(); n.next != null; n = n.next) {
				if(n.entry!=null && n.entry.isSpecial()){
					return true;
				}
			}
		}
		
		return false;
		
	}
	
	public static String toJavaName(String s) {
		return s.replaceAll("\\.", "___");
	}

	public static String fromJavaName(String s) {
		return s.replaceAll("___", ".");
	}

	private static Object[] buildArgumentsFromContext(Method m) {

		Object[] args = new Object[m.getParameterCount()];
		Annotation[][] pa = m.getParameterAnnotations();

		for (int parameter = 0; parameter < pa.length; parameter++) {
			for (int annotation = 0; annotation < pa[parameter].length; annotation++) {
				if (pa[parameter][annotation] instanceof ReleaseParam) {
					ReleaseParam arg = (ReleaseParam) pa[parameter][annotation];
					args[parameter] = context.get(arg.value()).getLeft();
				}
			}
		}

		return args;

		/*
		 * Object[] args = new Object[m.getParameterCount()];
		 * 
		 * Class parent = m.getDeclaringClass();
		 * 
		 * Field[] fields = parent.getDeclaredFields();
		 * 
		 * for (int parameter = 0; parameter < m.getParameterCount();
		 * parameter++) { String argName = null;
		 * 
		 * for(Field f : fields){ try {
		 * if(f.getName().equalsIgnoreCase(m.getName() + "_arg" + parameter))
		 * argName = (String)f.get(null); } catch (IllegalArgumentException |
		 * IllegalAccessException e) { // TODO Auto-generated catch block
		 * e.printStackTrace(); } }
		 * 
		 * assert(argName!=null); args[parameter] =
		 * context.get(argName).getLeft(); }
		 */

		// return args;
	}

	public static CheckResult checkMethodCall(List<Label> formalLabels, List<Taint<Label>> actualTaints) {

		// check each pair.
		if (formalLabels.size() != actualTaints.size()) {
			System.out.println("[MONITOR] System Integrity Violation. Mismatch in Formals / Actuals Arity");
			System.exit(1);
		}

		for (int i = 0; i < formalLabels.size(); i++) {
			CheckResult r = checkPair(formalLabels.get(i), actualTaints.get(i));

			if (!r.ok()) {
				return r;
			}
		}

		return CheckResult.instanceOk();
	}

	public static CheckResult checkMethodReturn(Label formalLabel, Taint<Label> actualTaint) {

		CheckResult r = checkPair(formalLabel, actualTaint);

		if (!r.ok()) {
			return r;
		}

		return CheckResult.instanceOk();
	}

}
