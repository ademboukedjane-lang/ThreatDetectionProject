package threatdetector.service;

import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.atomic.AtomicInteger;
import threatdetector.model.ScanItem;
import threatdetector.model.ScanResult;
 
public class ScanCoordinator {

    private ThreatAnalyze analyzer;
    private ExecutorService pool;

    public ScanCoordinator(ThreatAnalyze analyzer) {
        this.analyzer = analyzer;
        this.pool = Executors.newFixedThreadPool(4); 
    }

    public synchronized void submitAll(List<ScanItem> items, final ScanListener listener) {
        if (pool.isShutdown()) {
            pool = Executors.newFixedThreadPool(4);
        }

        final int total = items.size();        final AtomicInteger done = new AtomicInteger(0);

        for (final ScanItem item : items) {
            try {
                pool.submit(new Runnable() {
                    public void run() {
                        listener.onStarted(item);

                        ScanResult result;
                        try {
                            result = analyzer.analyze(item);
                        } catch (Exception e) {
                            result = ScanResult.notVerified(item, "Unexpected error");
                        }

                        if (Thread.currentThread().isInterrupted()) {
                            return; 
                        }
                        listener.onFinished(result);
                        listener.onProgress(done.incrementAndGet(), total);
                    }
                });
            } catch (RejectedExecutionException e) {
                return;
            }
        }
    }

    public synchronized void cancel() {
        pool.shutdownNow();
    }

    public synchronized void shutdown() {
        pool.shutdownNow();
    }
}