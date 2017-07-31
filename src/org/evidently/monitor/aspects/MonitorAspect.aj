package org.evidently.monitor.aspects;

import java.lang.annotation.Annotation;
import java.lang.annotation.AnnotationFormatError;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import org.aspectj.lang.JoinPoint;
import org.aspectj.lang.reflect.MethodSignature;
import org.evidently.annotations.ReleasePolicyFor;
import org.evidently.annotations.Sink;
import org.evidently.annotations.Source;
import org.evidently.monitor.CheckResult;
import org.evidently.monitor.Label;
import org.evidently.monitor.SecurityLabelManager;
import org.evidently.monitor.TaintStoreMergeTracker;
import org.reflections.Reflections;
import org.reflections.scanners.MethodAnnotationsScanner;
import org.reflections.scanners.SubTypesScanner;
import org.reflections.scanners.TypeAnnotationsScanner;
import org.reflections.util.ClasspathHelper;
import org.reflections.util.ConfigurationBuilder;

import edu.columbia.cs.psl.phosphor.runtime.MultiTainter;
import edu.columbia.cs.psl.phosphor.runtime.Taint;
import edu.columbia.cs.psl.phosphor.Configuration;;

aspect MonitorAspect {

	static {
		// Configuration.derivedTaintListener = new TaintStoreMergeTracker();
		// DON'T REMOVE THIS -- it's needed to prime the class loader cache.
		Reflections reflections = new Reflections(
				new ConfigurationBuilder().setUrls(ClasspathHelper.forPackage("org.evidently.policy")).setScanners(
						new SubTypesScanner(), new TypeAnnotationsScanner(), new MethodAnnotationsScanner()));

		Set<Method> methods = reflections.getMethodsAnnotatedWith(ReleasePolicyFor.class);

		for (Method mm : methods) {
			Annotation[][] as = mm.getParameterAnnotations();

			for (int i = 0; i < as.length; i++) {
				for (int j = 0; j < as[i].length; j++) {
					System.out.println(as[i][j]);
				}
			}
		}

	}

	/**
	 * This joinpoint performs several functions related to method calls.
	 * 
	 * 1. The first job of the before monitor point is to ensure that all of the
	 * parameters to the function being called do not violate the Denning
	 * lattice rules for information flow. If they do, the monitor will attempt
	 * to locate a policy that supports this type of downgrading. Otherwise, the
	 * flow is not allowed.
	 * 
	 * 2. The method of determining this is by fetching the labels on each
	 * argument comparing them against the methods own declared levels. 2. After
	 * checking enforcement, this joinpoint should compute the new label for the
	 * variable being passed around.
	 */

	public void checkMethodCall(JoinPoint thisJoinPoint) {
		AspectConfig.traceCall(thisJoinPoint); // log that we've been here.

		MethodSignature sig = (MethodSignature) thisJoinPoint.getSignature();

		// determine the the set of labels on the
		List<Label> formalLabels = formalParametersToLabels(sig);
		List<Taint<Label>> actualTaints = argsToTaints(thisJoinPoint.getArgs());

		// note this will update labels as needed.
		CheckResult result = SecurityLabelManager.checkMethodCall(formalLabels, actualTaints);

		if (result.ok()) {
			AspectConfig.log(thisJoinPoint, "Flow OK");
		} else {
			AspectConfig.reportViolation(thisJoinPoint, result.getMessage());
		}

	}

	public void checkMethodReturn(JoinPoint thisJoinPoint, Object returnValue) {
		AspectConfig.traceReturn(thisJoinPoint);

		// log that we've been here.
		MethodSignature sig = (MethodSignature) thisJoinPoint.getSignature();

		// what it should be
		try {
			Label formalLabel = returnTypeToLabel(sig);
			Taint<Label> actualTaint = returnValueToTaints(returnValue);

			// note this will update labels as needed.
			CheckResult result = SecurityLabelManager.checkMethodReturn(formalLabel, actualTaint);

			if (result.ok()) {
				AspectConfig.log(thisJoinPoint, "Flow OK");
			} else {
				AspectConfig.reportViolation(thisJoinPoint, result.getMessage());
			}
		} catch (AnnotationFormatError e) {
			e.printStackTrace();
		}

	}

	pointcut invoke(): call(* *(..)) 
	    && !within(org.evidently.examples.translated.PasswordChecker2) 
	    &&!within(org.evidently.monitor.CheckResult) 
	    &&  !within(org.evidently.monitor.Label)
	    && !cflow(call(* org.evidently.monitor.SecurityLabelManager.register(..)))
	    && !cflow(call(* org.evidently.monitor.SecurityLabelManager.update(..)))
	    && !cflow(call(* org.evidently.monitor.SecurityLabelManager.inCache(..)))	    
	    && !cflow(call(* org.evidently.monitor.SecurityLabelManager.getTaint(..)))
	    && !(within(org.evidently.monitor.aspects.AspectConfig)) 	    
	    
	    && !cflow(call(* MonitorAspect.checkMethodCall(..))) 
	    && !within(MonitorAspect) 
	    && !within(org.evidently.monitor.SecurityLabelManager)
	    && !within(org.evidently.examples.translated.Crash)
	    && !within(org.reflections.*) 
	    && !within(org.reflections.util.ClasspathHelper)
	    && !cflow(call(* org.reflections.util.ClasspathHelper.forPackage(..)))
	    && !within(edu.columbia.*) 
	    && !within(org.evidently.annotations.*)
	    && !within(org.evidently.flowpoints.*)
	    && !within(org.evidently.monitor.Pair);

	before(): invoke()  {
		// if(AspectConfig.isReady()){
		checkMethodCall(thisJoinPoint);
		// }
	}

	after() returning(Object r) : invoke(){
		// if(AspectConfig.isReady()){
		checkMethodReturn(thisJoinPoint, r);
		// }
	}

	private Taint<Label> returnValueToTaints(Object o) {
		Taint<Label> t = SecurityLabelManager.getInstance().inCache(o);
		if (t!=null) {
			return t;
		} else {
			return new Taint<Label>(SecurityLabelManager.defaultLabel());
		}
	}

	private List<Taint<Label>> argsToTaints(Object[] args) {
		List<Taint<Label>> labels = new ArrayList<Taint<Label>>();

		for (Object arg : args) {

			Taint<Label> t = SecurityLabelManager.getInstance().inCache(arg);
			
			if (t!=null) {
				labels.add(t);
			} else {
				labels.add(new Taint<Label>(SecurityLabelManager.defaultLabel()));
			}
		}

		return labels;
	}

	private Label returnTypeToLabel(MethodSignature sig) {

		Method m = sig.getMethod();
		Annotation[] pa = m.getAnnotations();

		String[] sinks = SecurityLabelManager.defaultSinks();
		String[] sources = SecurityLabelManager.defaultSources();

		for (int annotation = 0; annotation < pa.length; annotation++) {
			// a label is complete when we have a sink source pair.
			if (pa[annotation] instanceof Sink) {
				sinks = ((Sink) pa[annotation]).value();
			} else if (pa[annotation] instanceof Source) {
				sources = ((Source) pa[annotation]).value();
			}
		}

		return new Label(sinks, sources);
	}

	private List<Label> formalParametersToLabels(MethodSignature sig) {
		// TODO -- infer other half of label

		// TODO -- to support stubs, just look them up here rather than fetching
		// them
		// directly from the arguments.

		Method m = sig.getMethod();
		Annotation[][] pa = m.getParameterAnnotations();

		List<Label> labels = new ArrayList<Label>();

		for (int parameter = 0; parameter < pa.length; parameter++) {
			// Default for unannotated (no restriction)
			String[] sinks = SecurityLabelManager.defaultSinks();
			String[] sources = SecurityLabelManager.defaultSources();

			for (int annotation = 0; annotation < pa[parameter].length; annotation++) {
				// a label is complete when we have a sink source pair.
				if (pa[parameter][annotation] instanceof Sink) {
					sinks = ((Sink) pa[parameter][annotation]).value();
				} else if (pa[parameter][annotation] instanceof Source) {
					sources = ((Source) pa[parameter][annotation]).value();
				}
			}

			labels.add(new Label(sinks, sources));
		}

		return labels;
	}

}
