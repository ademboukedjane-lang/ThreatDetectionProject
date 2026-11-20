package threatdetector.service.rules;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.Test;

import threatdetector.model.InputType;
import threatdetector.model.RuleHit;
import threatdetector.model.ScanItem;

class UrgencyLanguageRuleTest {

    @Test
    void testUrgentMessage() {
        UrgencyLanguageRule rule = new UrgencyLanguageRule();
        ScanItem item = new ScanItem(1, InputType.MESSAGE,
                "Your account is urgent, act immediately!");

        RuleHit result = rule.evaluate(item);

        assertEquals(20, result.getPoints());
        assertTrue(result.isHit());
    }

    @Test
    void testArabicUrgency() {
        UrgencyLanguageRule rule = new UrgencyLanguageRule();
        ScanItem item = new ScanItem(2, InputType.MESSAGE,
                "يرجى التصرف فورا");

        RuleHit result = rule.evaluate(item);

        assertEquals(20, result.getPoints());
        assertTrue(result.isHit());
    }

    @Test
    void testNormalMessage() {
        UrgencyLanguageRule rule = new UrgencyLanguageRule();
        ScanItem item = new ScanItem(3, InputType.MESSAGE,
                "Hello, how are you?");

        RuleHit result = rule.evaluate(item);

        assertEquals(0, result.getPoints());
        assertFalse(result.isHit());
    }
}