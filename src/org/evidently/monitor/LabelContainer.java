package org.evidently.monitor;


public class LabelContainer<T> {
	private T data;
	private Label label;
	
	public LabelContainer(T data, Label label) {
		this.setData(data);
		this.setLabel(label);
	}

	public LabelContainer(T data, String[] sinks, String[] sources) {
		this.setData(data);
		this.setLabel(new Label(sinks, sources));
	}

	public T getData() {
		return data;
	}

	public void setData(T data) {
		this.data = data;
	}

	public Label getLabel() {
		return label;
	}

	public void setLabel(Label label) {
		this.label = label;
	}

}
