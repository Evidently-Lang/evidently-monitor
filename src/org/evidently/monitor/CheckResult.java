package org.evidently.monitor;

public class CheckResult {
	
	private boolean isOk;
	private Label to;
	private Label from;
	
	public CheckResult(){}

	public CheckResult(Label to, Label from)
	{
		this.setTo(to);
		this.setFrom(from);
		this.isOk= false;
	}
	
	
	
	
	public static CheckResult instanceOk(){
		CheckResult r = new CheckResult();
		r.isOk = true;
		
		return r;
	}
	
	

	
	public boolean ok(){
		return this.isOk;
	}

	public Label getTo() {
		return to;
	}

	public void setTo(Label to) {
		this.to = to;
	}

	public Label getFrom() {
		return from;
	}

	public void setFrom(Label from) {
		this.from = from;
	}
	
	public String getMessage()
	{
		return String.format("Invalid Flow Pair: From=%s, To=%s", getFrom().toString(), getTo().toString());
	}
	
}
