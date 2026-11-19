package threatdetector.ui;

import threatdetector.service.ScanService;

import javax.swing.JFrame;
import java.awt.Dimension;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;

/** The application window. Content lives in MainPanel. */
public class MainWindow extends JFrame {

    public MainWindow(ScanService service) {
        super("Multi-Threaded Threat Detector");
        setDefaultCloseOperation(DISPOSE_ON_CLOSE);
        setContentPane(new MainPanel(service));
        setMinimumSize(new Dimension(1050, 720));
        setSize(1240, 800);
        setLocationRelativeTo(null);
        addWindowListener(new WindowAdapter() {
            @Override
            public void windowClosed(WindowEvent e) {
                service.shutdown();
            }
        });
    }
}
