package org.evidently.monitor;


import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

public class Label {
	
	private Set<String> sinks;
	private Set<String> sources;
	
	public Label(Set<String> sinks, Set<String> sources) {
		this.sinks = sinks;
		this.sources = sources;
	}
	
	public Label(String[] sinks, String[] sources) {
		this(
				new HashSet<String>(Arrays.asList(sinks)),
				new HashSet<String>(Arrays.asList(sources))
			);		
	}
	
	
	public String toString(){		
		String format="(Sinks, {%s}), (Sources, {%s})";		
		return String.format(format, String.join(",", sinks), String.join(",", sources));
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
		return (from.sinks.containsAll(to.sinks) || to.sinks.size()==0) && 
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
		
		if(l.sinks.contains("ANY")){ return; }
		if(effectiveLabel.sinks.contains("ANY")){ return; }
		
		effectiveLabel.sinks.clear();
		effectiveLabel.sinks.addAll(l.sinks);
	}

}
