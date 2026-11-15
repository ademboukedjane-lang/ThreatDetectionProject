package threatdetector.service.rules;

import java.net.URI;
   
import threatdetector.model.InputType;
import threatdetector.model.RuleHit;
import threatdetector.model.ScanItem;
import threatdetector.service.Rule;

public class IpHostRule implements Rule{
	public boolean appliesTo(InputType type) {
		return type == InputType.URL;
	}
	@Override
	public  RuleHit evaluate(ScanItem item) {
		String content = item.getContent().trim();
		try {
			URI uri = URI.create(content);
			String host = uri.getHost();
			if(isIPv4(host)) {
				return new RuleHit(30, "URL uses IP adderqq insted of a domain name");
			}
		} catch (IllegalArgumentException e) {
			return RuleHit.none();
		}
			return RuleHit.none();
		
			}
	
	public boolean isIPv4(String host) {
		if(host == null) {
			return false;
		}
		String[] parts = host.split("\\.");
		if(parts.length!=4) {
			return false;
		}
		for(String part : parts) {
			try {
				int number = Integer.parseInt(part);
				if(number < 0 || number > 255) {
					return false;
				}
			}catch (NumberFormatException e) {
				return false;
			}
		}
		
		return false;
	}

}
