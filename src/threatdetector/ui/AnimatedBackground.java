package threatdetector.ui;

import javax.swing.JComponent;
import javax.swing.Timer;
import java.awt.Color;
import java.awt.Graphics2D;
import java.awt.RadialGradientPaint;
import java.awt.geom.Point2D;
import java.util.Random;

/** Animated "network" background: glowing blobs + moving dots linked by lines. */
public final class AnimatedBackground {
    private static final int N = 55;
    private static final double LINK = 140;

    private final Timer timer;
    private final Random rnd = new Random();
    private final double[] x = new double[N], y = new double[N];
    private final double[] vx = new double[N], vy = new double[N];
    private int w, h;
    private double phase;

    public AnimatedBackground(JComponent target) {
        for (int i = 0; i < N; i++) {
            vx[i] = (rnd.nextDouble() - 0.5) * 1.2;
            vy[i] = (rnd.nextDouble() - 0.5) * 1.2;
        }
        timer = new Timer(40, e -> {
            step();
            target.repaint();
        });
    }

    public void start() { if (!timer.isRunning()) timer.start(); }
    public void stop()  { timer.stop(); }

    private void step() {
        phase += 0.012;
        for (int i = 0; i < N; i++) {
            x[i] += vx[i];
            y[i] += vy[i];
            if (x[i] < 0 || x[i] > w) vx[i] = -vx[i];
            if (y[i] < 0 || y[i] > h) vy[i] = -vy[i];
        }
    }

    private void ensure(int width, int height) {
        if (width == w && height == h) return;
        w = width;
        h = height;
        for (int i = 0; i < N; i++) {
            x[i] = rnd.nextDouble() * w;
            y[i] = rnd.nextDouble() * h;
        }
    }

    public void paint(Graphics2D g, int width, int height) {
        ensure(width, height);
        blob(g, width * (0.25 + 0.15 * Math.sin(phase)), height * (0.30 + 0.20 * Math.cos(phase * 0.8)),
                Math.max(width, height) * 0.45, new Color(30, 120, 255, 60));
        blob(g, width * (0.75 + 0.15 * Math.cos(phase * 0.7)), height * (0.70 + 0.15 * Math.sin(phase)),
                Math.max(width, height) * 0.40, new Color(34, 211, 238, 40));

        for (int i = 0; i < N; i++) {
            for (int j = i + 1; j < N; j++) {
                double dx = x[i] - x[j], dy = y[i] - y[j];
                double d = Math.sqrt(dx * dx + dy * dy);
                if (d < LINK) {
                    g.setColor(new Color(40, 140, 255, (int) ((1 - d / LINK) * 90)));
                    g.drawLine((int) x[i], (int) y[i], (int) x[j], (int) y[j]);
                }
            }
        }
        g.setColor(new Color(34, 211, 238, 150));
        for (int i = 0; i < N; i++) {
            g.fillOval((int) x[i] - 2, (int) y[i] - 2, 4, 4);
        }
    }

    private static void blob(Graphics2D g, double cx, double cy, double r, Color c) {
        g.setPaint(new RadialGradientPaint(new Point2D.Double(cx, cy), (float) r,
                new float[] {0f, 1f},
                new Color[] {c, new Color(c.getRed(), c.getGreen(), c.getBlue(), 0)}));
        g.fillRect((int) (cx - r), (int) (cy - r), (int) (2 * r) + 1, (int) (2 * r) + 1);
    }
}
