package org.evidently.monitor;


import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.evidently.policy.PolicyElementType;

public class Label {
	
	private Set<String> sinks;
	private Set<String> sources;
	private List<Pair<PolicyElementType, String>> policyElementTypes = new ArrayList<Pair<PolicyElementType, String>>();
	
	
	public Label(Set<String> sinks, Set<String> sources) {
		this.sinks = sinks;
		this.sources = sources;
	}
	
	public Label(Set<String> sinks, Set<String> sources, PolicyElementType policyElementType, String policyElementName) {
		this.sinks = sinks;
		this.sources = sources;		

		// it could be multiple things, I suppose
		policyElementTypes.add(new Pair<PolicyElementType, String>(policyElementType, policyElementName));		
	}
	
	public Label(String[] sinks, String[] sources) {
		this(
				new HashSet<String>(Arrays.asList(sinks)),
				new HashSet<String>(Arrays.asList(sources))
			);		
	}
	
	
	public Label(String[] sinks, String[] sources, PolicyElementType policyElementType, String policyElementName) {
		this(
				new HashSet<String>(Arrays.asList(sinks)),
				new HashSet<String>(Arrays.asList(sources)),
				policyElementType, 
				policyElementName
			);		
	}
	
	public boolean isSpecial()
	{
		return this.policyElementTypes.size() > 0;
	}
	
	public List<Pair<PolicyElementType, String>> getPolicyElementTypes()
	{
		return this.policyElementTypes;
	}
	
	public String toString(){		
		
		String format="(Sinks, {%s}), (Sources, {%s}), (PolicyElements, {%s})";		
		
		List<String> elements = new ArrayList<String>();
		
		for(Pair<PolicyElementType,String> element : this.policyElementTypes){
			elements.add(String.format("[%s, %s]", element.getLeft(), element.getRight()));
		}
		
		return String.format(format, String.join(",", sinks), String.join(",", sources), String.join(",", elements));
	}
	
	public static void noAny(Set<String> s)
	{
		s.remove("ANY");
	}
	
	public static boolean isValidDenningFlow(Label from, Label to)
	{
		noAny(from.sources);
		noAny(to.sources);
		
		noAny(to.sinks);
		noAny(from.sinks);

		// sinks must be NO MORE places 
		// that is, to.sinks must subset 
		return (
					from.sinks.containsAll(to.sinks) 
						|| 
					to.sinks.size()==0
				) 
				&& 
				// sources must be NO LESS places
				(
					to.sources.containsAll(from.sources)
						||
					to.sources.size()==0
				);
		
	}
	
	// fix merge process. don't merge if the other one is an ANY.
	public static void mergeSource(Label effectiveLabel, Label l) {
		
		if(l.sources.contains("ANY")){ return; }
		if(effectiveLabel.sources.contains("ANY")){ return; }
		
		effectiveLabel.sources.addAll(l.sources);
	}

	public static void mergeSinks(Label effectiveLabel, Label l) {
		
		if(l.sinks.contains("ANY") || l.sinks.size()==0){ return; }
		if(effectiveLabel.sinks.contains("ANY")){ return; }
		
		effectiveLabel.sinks.clear();
		effectiveLabel.sinks.addAll(l.sinks);
	}

	public void updateContexts(Object o, HashMap<String, Pair<Object, Label>> context) {

		for(Pair<PolicyElementType, String> p : this.getPolicyElementTypes()){
			context.put(p.getRight(), new Pair<Object,Label>(o, this));
		}
			
		
	}

	public List<String> getPolicyElementNames() {
		
		List<String> names = new ArrayList<String>();
		
		for(Pair<PolicyElementType, String> p : this.getPolicyElementTypes()){
			names.add(p.getRight());
		}
			
		
		return names;
	}

}
