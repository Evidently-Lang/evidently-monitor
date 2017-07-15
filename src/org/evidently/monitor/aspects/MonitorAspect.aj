package org.evidently.monitor.aspects;


import java.lang.annotation.Annotation;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.List;

import org.aspectj.lang.JoinPoint;
import org.aspectj.lang.reflect.MethodSignature;
import org.evidently.annotations.Sink;
import org.evidently.annotations.Source;
import org.evidently.monitor.CheckResult;
import org.evidently.monitor.Label;
import org.evidently.monitor.SecurityLabelManager;

import edu.columbia.cs.psl.phosphor.runtime.MultiTainter;
import edu.columbia.cs.psl.phosphor.runtime.Taint;

aspect MonitorAspect {
	
		enum MonitorMode { WARN, ENFORCE }
		
		private MonitorMode enforcementMode = MonitorMode.WARN;

	    /**  
	     * This joinpoint performs several functions related to method calls.
	     * 
	     * 1. The first job of the before monitor point is to ensure
	     * 	  that all of the parameters to the function being called  
	     * 	  do not violate the Denning lattice rules for information flow. 
	     * 	  If they do, the monitor will attempt to locate a policy that supports 
	     *    this type of downgrading. Otherwise, the flow is not allowed.  
	     *    
	     * 2. The method of determining this is by fetching the labels on each argument 
	     *    comparing them against the methods own declared levels. 
	     * 2. After checking enforcement, this joinpoint should compute the new label for 
	     *    the variable being passed around. 
	     */

		public void checkMethodCall(JoinPoint thisJoinPoint)
		{
	        trace(thisJoinPoint); // log that we've been here.
	        
	        
	        MethodSignature sig = (MethodSignature)thisJoinPoint.getSignature();
	        	        
	        // determine the the set of labels on the 
	        List<Label> formalLabels = formalParametersToLabels(sig);
	        List<Taint<Label>> actualTaints = argsToTaints(thisJoinPoint.getArgs());
	        

	        // note this will update labels as needed. 
	        CheckResult result = SecurityLabelManager.checkMethodCall(formalLabels, actualTaints);
	        
	        if(result.ok()){
	        	log(thisJoinPoint, "Flow OK");
	        }else{
	        	reportViolation(thisJoinPoint, result.getMessage());
	        }

		}
	
	    pointcut invoke(): call(* *(..)) 
	    && !within(org.evidently.examples.translated.PasswordChecker2) 
	    &&!within(org.evidently.monitor.CheckResult) 
	    &&  !within(org.evidently.monitor.Label) 
	    && !cflow(call(* org.evidently.monitor.SecurityLabelManager.register(..)))
	    && !cflow(call(* org.evidently.monitor.SecurityLabelManager.inCache(..)))	    
	    && !cflow(call(* org.evidently.monitor.SecurityLabelManager.getTaint(..))) 	    
	    && !cflow(call(* MonitorAspect.checkMethodCall(..))) 
	    && !within(MonitorAspect) 
	    && !within(org.evidently.monitor.SecurityLabelManager) 
	    && !within(edu.columbia.*) 
	    && !within(org.evidently.annotations.*);
	
	    before(): invoke()  {
	    	checkMethodCall(thisJoinPoint);
	    }
	    
	    private List<Taint<Label>> argsToTaints(Object[] args){
	    	List<Taint<Label>> labels = new ArrayList<Taint<Label>>();
	        
	    	for(Object arg : args){
	    		
	    		if(SecurityLabelManager.getInstance().inCache(arg)){
	    			
	    			Taint<Label> t = SecurityLabelManager.getInstance().getTaint(arg);
	    			
	    			labels.add(t);
	    			
	    		}else{
	    			labels.add(new Taint<Label>(SecurityLabelManager.defaultLabel()));
	    		}
	    	}
	    	
	    	return labels;
	    }
	    
	    private List<Label> formalParametersToLabels(MethodSignature sig){
	    	//TODO -- infer other half of label
	    	
	    	//TODO -- to support stubs, just look them up here rather than fetching them 
	    	// directly from the arguments. 
	    	
	        Method m = sig.getMethod();
	        Annotation[][] pa = m.getParameterAnnotations();

	        List<Label> labels = new ArrayList<Label>();
	        
	        for(int parameter=0; parameter < pa.length; parameter++){
	        	// Default for unannotated (no restriction) 
	        	String[] sinks   = SecurityLabelManager.defaultSinks();
	        	String[] sources = SecurityLabelManager.defaultSources();
	        	
	        	for(int annotation=0; annotation < pa[parameter].length; annotation++){
	        		// a label is complete when we have a sink source pair.
	        		if(pa[parameter][annotation] instanceof Sink){
	        			sinks = ((Sink)pa[parameter][annotation]).value();
	        		}
	        		else if(pa[parameter][annotation] instanceof Source){
	        			sources = ((Source)pa[parameter][annotation]).value();	        			
	        		}
	        	}
	        	
	        	labels.add(new Label(sinks, sources));
	        }
	        
	        return labels;
	    }
	    
	    private void reportViolation(JoinPoint jp, String message) {

	    	System.out.println(
					String.format("[Evidently] [IFC VIOLATION] \n\tDesc=%s\n\tMessage=%s"
							, jp.toLongString()
							, message
							)
				);
	    		
    		if(enforcementMode==MonitorMode.ENFORCE) {
    			// exit!
    			System.exit(-1);
    		}
	    }

	    private void log(JoinPoint jp, String message) {

	    	System.out.println(
					String.format("[Evidently] [TRACE] \n\tDesc=%s\n\tMessage=%s"
							, jp.toLongString()
							, message
							)
	    				);
	    }

	    private void trace(JoinPoint jp) {

	    	System.out.println(
					String.format("[Evidently] [TRACE] \n\tDesc=%s"
							, jp.toLongString()
							)
	    				);
	    }
	}


