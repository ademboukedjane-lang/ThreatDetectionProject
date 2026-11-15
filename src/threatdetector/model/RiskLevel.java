package threatdetector.model;

public enum RiskLevel {
	  LOW,          
	    MEDIUM,       
	    HIGH,         
	    NOT_VERIFIED;

	   
	    public static RiskLevel fromScore(int score) {
	        if (score >= 60) return HIGH;
	        if (score >= 30) return MEDIUM;
	        return LOW;
	    }
}
