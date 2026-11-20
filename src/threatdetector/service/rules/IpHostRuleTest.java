package threatdetector.service.rules;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.Test;

import threatdetector.model.InputType;
import threatdetector.model.RuleHit;
import threatdetector.model.ScanItem;

class IpHostRuleTest {

    @Test
    void testIpAddress() {
        IpHostRule rule = new IpHostRule();
        ScanItem item = new ScanItem(1, InputType.URL, "http://192.168.1.1");

        RuleHit result = rule.evaluate(item);

        assertEquals(30, result.getPoints());
        assertTrue(result.isHit());
    }

    @Test
    void testDomainName() {
        IpHostRule rule = new IpHostRule();
        ScanItem item = new ScanItem(2, InputType.URL, "https://google.com");

        RuleHit result = rule.evaluate(item);

        assertEquals(0, result.getPoints());
        assertFalse(result.isHit());
    }

    @Test
    void testAppliesTo() {
        IpHostRule rule = new IpHostRule();

        assertTrue(rule.appliesTo(InputType.URL));
        assertFalse(rule.appliesTo(InputType.MESSAGE));
    }
}