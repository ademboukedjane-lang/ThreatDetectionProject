package threatdetector;

import javax.swing.SwingUtilities;
import threatdetector.ui.MainWindow;
import threatdetector.service.ScanCoordinator;
import threatdetector.service.ThreatAnalyze;
import threatdetector.service.RuleBasedAnalyzer;

public class main {

    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> {
            
            // 1. نستعملو الكلاس الحقيقي اللي لقيناه في الصورة
            ThreatAnalyze analyzer = new RuleBasedAnalyzer();
            
            // 2. نعطوه للـ Coordinator
            ScanCoordinator coordinator = new ScanCoordinator(analyzer);
            
            // 3. نفتحو الواجهة
            MainWindow window = new MainWindow(coordinator, 4);
            window.setVisible(true);
            
        });
    }
}