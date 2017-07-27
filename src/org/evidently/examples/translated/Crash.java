package org.evidently.examples.translated;

import java.lang.annotation.Annotation;
import java.lang.reflect.Method;
import java.util.Set;

import org.evidently.annotation.Policy;
import org.evidently.annotations.ReleasePolicyFor;
import org.evidently.annotations.Sink;
import org.evidently.annotations.Source;
import org.evidently.monitor.Label;
import org.evidently.monitor.Pair;
import org.evidently.monitor.SecurityLabelManager;
import org.evidently.policy.PolicyElementType;
import org.evidently.policy.numberguesser.PolicyReleaseGuessesToAdmin;
import org.reflections.Reflections;
import org.reflections.scanners.MethodAnnotationsScanner;
import org.reflections.scanners.SubTypesScanner;
import org.reflections.scanners.TypeAnnotationsScanner;
import org.reflections.util.ClasspathHelper;
import org.reflections.util.ConfigurationBuilder;

public class Crash {
		
	
	public static int getPasswordGuess(@Source("UI")  int a)
	{
		return 0;
	}

	public static void main(String args[]) throws NoSuchMethodException, SecurityException {

		PolicyReleaseGuessesToAdmin a = new PolicyReleaseGuessesToAdmin();
		
		Method[] m = a.getClass().getMethods();
		
		for(Method mm : m){
			if(mm.getName().equals("release_1_Guess___guess")){
				Annotation[][] as = mm.getParameterAnnotations();
				
				for(int i=0; i< as.length; i++){
					for(int j=0; j<as[i].length; j++){
						System.out.println(as[i][j]);
					}
				}
				
			}
		}
				
				//getMethod("release_1_Guess___guess", Integer.class, Boolean.class);

		
		Reflections reflections = new Reflections(new ConfigurationBuilder()
			     .setUrls(ClasspathHelper.forPackage("org.evidently.policy"))
			     .setScanners(new SubTypesScanner(), 
			                  new TypeAnnotationsScanner(),
			                  new MethodAnnotationsScanner()
			    		 ));
		
		Set<Class<?>> allPolicies = reflections.getTypesAnnotatedWith(Policy.class);
		
		for(Class c : allPolicies){
			System.out.println(String.format("[Evidently] [Policy] Loaded Policy: %s", c.getName()));
		}

		System.out.println(String.format("[Evidently] [Policy] Looking for Policies that can declassify any of the following: "));
		
		
		Set<Method> methods = reflections.getMethodsAnnotatedWith(ReleasePolicyFor.class);
		
		for(Method mm : methods){
			Annotation[][] as = mm.getParameterAnnotations();
			
			for(int i=0; i< as.length; i++){
				for(int j=0; j<as[i].length; j++){
					System.out.println(as[i][j]);
				}
			}
		}

		
		
		if(1==1){
			System.out.println("test");
		}
	}
}
