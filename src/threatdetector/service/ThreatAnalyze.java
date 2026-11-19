package threatdetector.service;

import threatdetector.model.ScanItem;
import threatdetector.model.ScanResult;

public interface ThreatAnalyze {
    ScanResult analyze(ScanItem item);

}