package threatdetector.service;

import java.io.File;
import java.util.List;

import threatdetector.model.InputType;
import threatdetector.model.ScanItem;
import threatdetector.model.ScanResult;

public class ScanCoordinator {

    private ThreatAnalyze analyzer;

    private boolean cancelled = false;

    public ScanCoordinator(ThreatAnalyze analyzer) {
        this.analyzer = analyzer;
    }

    public void submitAll(List<ScanItem> items, ScanListener listener) {

        cancelled = false;

        int total = items.size();
        int done = 0;

        for (ScanItem item : items) {

            if (cancelled) {
                break;
            }

            listener.onStarted(item);

            ScanResult result;

            try {
                result = analyzer.analyze(item);

            } catch (Exception e) {
                result = ScanResult.notVerified(item, "Unexpected error");
            }

            listener.onFinished(result);

            done++;
          listener.onProgress(done, total);
        }
    }

    public void cancel() {
        cancelled = true;
    }

    public void shutdown() {
        cancelled = true;
    }

	
}
