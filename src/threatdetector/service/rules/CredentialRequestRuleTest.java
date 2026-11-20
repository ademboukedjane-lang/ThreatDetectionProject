package threatdetector.service.rules;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.Test;

import threatdetector.model.InputType;
import threatdetector.model.RuleHit;
import threatdetector.model.ScanItem;

class CredentialRequestRuleTest {

    @Test
    void testPasswordRequest() {
        CredentialRequestRule rule = new CredentialRequestRule();
        ScanItem item = new ScanItem(1, InputType.MESSAGE,
                "Please enter your password");

        RuleHit result = rule.evaluate(item);

        assertEquals(30, result.getPoints());
        assertTrue(result.isHit());
    }

    @Test
    void testOtpRequest() {
        CredentialRequestRule rule = new CredentialRequestRule();
        ScanItem item = new ScanItem(2, InputType.MESSAGE,
                "Send me your OTP code");

        RuleHit result = rule.evaluate(item);

        assertEquals(30, result.getPoints());
        assertTrue(result.isHit());
    }

    @Test
    void testNormalMessage() {
        CredentialRequestRule rule = new CredentialRequestRule();
        ScanItem item = new ScanItem(3, InputType.MESSAGE,
                "Have a nice day!");

        RuleHit result = rule.evaluate(item);

        assertEquals(0, result.getPoints());
        assertFalse(result.isHit());
    }
}