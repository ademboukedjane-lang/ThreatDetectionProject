package threatdetector.service.rules;

import java.util.Locale;

import threatdetector.model.InputType;
import threatdetector.model.RuleHit;
import threatdetector.model.ScanItem;
import threatdetector.service.Rule;

public class CredentialRequestRule implements Rule {
	@Override
	public boolean appliesTo(InputType type) {
		return type == InputType.MESSAGE;
	}
	@Override
	public RuleHit evaluate(ScanItem item) {
		String content = item.getContent().toLowerCase(Locale.ROOT);
		String[] sensitiveWords = {"password","passcode","otp", "verification code","security code","credit card",
				"card number","cvv","mot de passe","code de verification","كلمة المرور","كلمة السر","رمز التحقق",
				"رمز التأكيد","الرقم السري","البطاقة البنكية","رقم البطاقة"
	            
	        };
		for(String word : sensitiveWords) {
			if(content.contains(word)) {
				return new RuleHit(30 , "message requeste sensitive informaton language");
			}
		}
		return RuleHit.none();
				}


}
