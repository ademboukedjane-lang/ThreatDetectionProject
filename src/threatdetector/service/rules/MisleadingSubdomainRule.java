package threatdetector.service.rules;


import java.net.URI;
import java.util.Locale;

import threatdetector.model.InputType;
import threatdetector.model.RuleHit;
import threatdetector.model.ScanItem;
import threatdetector.service.Rule;

public class MisleadingSubdomainRule implements Rule {
	  @Override
	    public boolean appliesTo(InputType type) {
	        return type == InputType.URL;
	    }

	    @Override
	    public RuleHit evaluate(ScanItem item) {

	        String content = item.getContent().trim();

	        try {
	            URI uri = URI.create(content);

	            String host = uri.getHost();

	            if (host == null) {
	                return RuleHit.none();
	            }

	            host = host.toLowerCase(Locale.ROOT);

	            String[] parts = host.split("\\.");

	            String[] brands= {"paypal", "google","amazon","facebook","microsoft","apple","netflix",
	            		"instagram","twitter","youtube", "yahoo","gmail","dropbox","spotify","steam","discord",
	            		"tiktok","binance","coinbase","ebay","chase","visa","mastercard"
	            	  
	            	};

	            
	            if (parts.length >= 5) {
	                return new RuleHit(25,
	                        "URL contains many subdomains");
	            }

	            
	            for (int i = 0; i < parts.length - 2; i++) {

	                for (String brand : brands) {

	                    if (parts[i].contains(brand)) {
	                        return new RuleHit(25,
	                                "Known brand name used in a suspicious subdomain");
	                    }
	                }
	            }

	        } catch (IllegalArgumentException e) {
	            return RuleHit.none();
	        }

	        return RuleHit.none();
	    }

}
