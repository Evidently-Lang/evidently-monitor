package org.evidently.monitor;

import edu.columbia.cs.psl.phosphor.runtime.Taint;

public class CheckResult {
	
	private boolean isOk;
	private Label to;
	private Label from;
	private Label res;
	private Taint<Label> relabel;
	public CheckResult(){}

	public CheckResult(Label to, Label from)
	{
		this.setTo(to);
		this.setFrom(from);
		this.isOk= false;
	}
	
	
	
	
	public CheckResult(Taint<Label> previousLHSTaint) {
		this.relabel = previousLHSTaint;
	}

	public static CheckResult instanceOk(){
		CheckResult r = new CheckResult();
		r.isOk = true;
		
		return r;
	}
	
	
	public static CheckResult instanceOk(Label res){
		CheckResult r = new CheckResult();
		r.isOk = true;		
		r.setRes(res);
		
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
		if(relabel!=null){
			return String.format("Attempt to remove label, previously: %s", relabel.toString());
		}else{
			return String.format("Invalid Flow Pair: From=%s, To=%s", getFrom().toString(), getTo().toString());
		}
	}

	public Label getRes() {
		return res;
	}

	public void setRes(Label res) {
		this.res = res;
	}
	
}
