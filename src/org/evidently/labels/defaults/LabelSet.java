package org.evidently.labels.defaults;

public class LabelSet {

	public String[] sinks() {
		return new String[] { "DB", "UI", "NET", "LOG" };
	}

	public String[] sources() {
		return new String[] { "DB", "UI", "NET", "LOG" };
	}
}
