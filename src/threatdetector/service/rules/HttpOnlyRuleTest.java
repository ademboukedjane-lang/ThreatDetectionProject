package threatdetector.service.rules;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.Test;

import threatdetector.model.InputType;
import threatdetector.model.RuleHit;
import threatdetector.model.ScanItem;

class HttpOnlyRuleTest {

    @Test
    void testHttpUrl() {

        HttpOnlyRule rule = new HttpOnlyRule();

        ScanItem item = new ScanItem(
                1, InputType.URL, "http://google.com");

        RuleHit result = rule.evaluate(item);

        assertEquals(20, result.getPoints());
        assertTrue(result.isHit());
    }

    @Test
    void testHttpsUrl() {

        HttpOnlyRule rule = new HttpOnlyRule();

        ScanItem item = new ScanItem(
                2, InputType.URL, "https://google.com");

        RuleHit result = rule.evaluate(item);

        assertEquals(0, result.getPoints());
        assertFalse(result.isHit());
    }

    @Test
    void testAppliesTo() {

        HttpOnlyRule rule = new HttpOnlyRule();

        assertTrue(rule.appliesTo(InputType.URL));
        assertFalse(rule.appliesTo(InputType.MESSAGE));
    }
}