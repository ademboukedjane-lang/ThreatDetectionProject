package threatdetector;

import javax.swing.SwingUtilities;

import threatdetector.ui.MainWindow;

public class main {

	public static void main(String[] args) {
		SwingUtilities.invokeLater(() -> new MainWindow().setVisible(true));
    }
}
