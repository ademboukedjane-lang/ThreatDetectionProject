package threatdetector.service.rules;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.Test;

import threatdetector.model.InputType;
import threatdetector.model.RuleHit;
import threatdetector.model.ScanItem;

class MisleadingSubdomainRuleTest {

    @Test
    void testSuspiciousBrandSubdomain() {
        MisleadingSubdomainRule rule = new MisleadingSubdomainRule();
        ScanItem item = new ScanItem(1, InputType.URL, "https://paypal.evil.com");

        RuleHit result = rule.evaluate(item);

        assertEquals(25, result.getPoints());
        assertTrue(result.isHit());
    }

    @Test
    void testNormalDomain() {
        MisleadingSubdomainRule rule = new MisleadingSubdomainRule();
        ScanItem item = new ScanItem(2, InputType.URL, "https://www.google.com");

        RuleHit result = rule.evaluate(item);

        assertEquals(0, result.getPoints());
        assertFalse(result.isHit());
    }

    @Test
    void testManySubdomains() {
        MisleadingSubdomainRule rule = new MisleadingSubdomainRule();
        ScanItem item = new ScanItem(3, InputType.URL,
                "https://a.b.c.d.example.com");

        RuleHit result = rule.evaluate(item);

        assertEquals(25, result.getPoints());
        assertTrue(result.isHit());
    }
}