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

}
