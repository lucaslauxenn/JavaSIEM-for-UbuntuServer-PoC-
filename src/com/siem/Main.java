package com.siem;

import com.siem.gui.SiemGui;
import javax.swing.SwingUtilities;

public class Main {
    public static void main(String[] args) {
        // Executa a interface Swing de forma segura na Event Dispatch Thread (EDT)
        SwingUtilities.invokeLater(() -> {
            SiemGui gui = new SiemGui();
            gui.setVisible(true);
        });
    }
}