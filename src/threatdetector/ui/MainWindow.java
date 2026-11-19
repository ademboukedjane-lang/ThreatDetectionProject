package threatdetector.ui;

import javax.swing.JFrame;
import java.awt.Dimension;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;

import threatdetector.service.ScanCoordinator;

public class MainWindow extends JFrame {

    private static final long serialVersionUID = 1L;

    private final ScanCoordinator coordinator;

    public MainWindow(ScanCoordinator coordinator, int workerCount) {
        super("Multi-Threaded Threat Detector");

        this.coordinator = coordinator;

        setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);

        setContentPane(new MainPanel(coordinator, workerCount));
    }
        
        
          {  setMinimumSize(new Dimension(1050, 720));
        setSize(1240, 800);
        setLocationRelativeTo(null);

        addWindowListener(new WindowAdapter() {
            @Override
            public void windowClosed(WindowEvent e) {
                coordinator.shutdown();
            }
        });
    }
}