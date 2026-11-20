package threatdetector.service;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.Test;

import threatdetector.model.InputType;
import threatdetector.model.RiskLevel;
import threatdetector.model.ScanItem;
import threatdetector.model.ScanResult;
import threatdetector.model.ScanStatus;

class RuleBasedAnalyzerTest {

    @Test
    void testUrgentPasswordMessage() {

        RuleBasedAnalyzer analyzer = new RuleBasedAnalyzer();

        ScanItem item = new ScanItem(
                1,
                InputType.MESSAGE,
                "URGENT! Send me your password immediately."
        );

        ScanResult result = analyzer.analyze(item);

        assertEquals(RiskLevel.MEDIUM, result.getLevel());
        assertEquals(ScanStatus.DONE, result.getStatus());
        assertEquals(2, result.getReasons().size());
    }

    @Test
    void testNormalMessage() {

        RuleBasedAnalyzer analyzer = new RuleBasedAnalyzer();

        ScanItem item = new ScanItem(
                2,
                InputType.MESSAGE,
                "Hello, how are you?"
        );

        ScanResult result = analyzer.analyze(item);

        assertEquals(RiskLevel.LOW, result.getLevel());
        assertTrue(result.getReasons().isEmpty());
    }

    @Test
    void testSuspiciousUrl() {

        RuleBasedAnalyzer analyzer = new RuleBasedAnalyzer();

        ScanItem item = new ScanItem(
                3,
                InputType.URL,
                "http://paypal.evil.com"
        );

        ScanResult result = analyzer.analyze(item);

        assertEquals(RiskLevel.MEDIUM, result.getLevel());
        assertEquals(2, result.getReasons().size());
    }
}