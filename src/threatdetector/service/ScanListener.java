package threatdetector.service;
import threatdetector.model.ScanItem;
import threatdetector.model.ScanResult;
public interface ScanListener {
void onStarted (ScanItem item );
void onFinished (ScanResult result);
void onProgress (int done , int total);

}
