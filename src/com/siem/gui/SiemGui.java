package com.siem.gui;

import com.siem.engine.SiemEngine;
import com.siem.factory.LogParserFactory;
import com.siem.models.LogEntry;
import com.siem.rules.CriticalPortBlockRule;
import com.siem.rules.RootLoginRule;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.io.PrintStream;

public class SiemGui extends JFrame {
    private final SiemEngine siemEngine;
    private final DefaultTableModel tableModel;
    private final JTextArea alertTextArea;
    private boolean isMonitoring = false;
    private Thread monitorThread;

    public SiemGui() {
        siemEngine = new SiemEngine();
        siemEngine.registerRule(new RootLoginRule());
        siemEngine.registerRule(new CriticalPortBlockRule());

        setTitle("Micro-SIEM Dashboard (Ubuntu Real-Time Logs)");
        setSize(950, 600);
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setLocationRelativeTo(null);
        setLayout(new BorderLayout(10, 10));

        // -----------------------------------------------------------------
        // 1. Painel Superior: Controles
        // -----------------------------------------------------------------
        JPanel topPanel = new JPanel(new BorderLayout());
        topPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        JLabel titleLabel = new JLabel("SIEM Security Monitor - Live Mode", JLabel.LEFT);
        titleLabel.setFont(new Font("Segoe UI", Font.BOLD, 18));
        topPanel.add(titleLabel, BorderLayout.WEST);

        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));

        JButton btnSimulate = new JButton("Simular Logs");
        JButton btnLiveMonitor = new JButton("Monitorar /var/log/auth.log");
        btnLiveMonitor.setBackground(new Color(40, 160, 80));
        btnLiveMonitor.setForeground(Color.WHITE);

        buttonPanel.add(btnSimulate);
        buttonPanel.add(btnLiveMonitor);
        topPanel.add(buttonPanel, BorderLayout.EAST);

        add(topPanel, BorderLayout.NORTH);


        // 2. Painel Central: Tabela de Logs Processados
        String[] columnNames = {"Data/Hora", "IP de Origem", "Nível", "Detalhes do Evento"};
        tableModel = new DefaultTableModel(columnNames, 0);
        JTable logTable = new JTable(tableModel);
        logTable.setFont(new Font("Segoe UI", Font.PLAIN, 12));
        logTable.setRowHeight(22);

        JScrollPane tableScrollPane = new JScrollPane(logTable);
        tableScrollPane.setBorder(BorderFactory.createTitledBorder("Logs Capturados no Sistema"));


        // 3. Painel Inferior: Terminal de Alertas
        alertTextArea = new JTextArea(10, 50);
        alertTextArea.setFont(new Font("Consolas", Font.BOLD, 12));
        alertTextArea.setBackground(new Color(20, 20, 20));
        alertTextArea.setForeground(new Color(255, 50, 50));
        alertTextArea.setEditable(false);

        JScrollPane alertScrollPane = new JScrollPane(alertTextArea);
        alertScrollPane.setBorder(BorderFactory.createTitledBorder("Alertas de Segurança Disparados (SOC)"));

        JSplitPane splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT, tableScrollPane, alertScrollPane);
        splitPane.setDividerLocation(300);
        add(splitPane, BorderLayout.CENTER);

        redirecionarSystemOut();

        // Eventos
        btnSimulate.addActionListener(e -> carregarLogsSimulados());

        btnLiveMonitor.addActionListener(e -> {
            if (!isMonitoring) {
                isMonitoring = true;
                btnLiveMonitor.setText("Parar Monitoramento");
                btnLiveMonitor.setBackground(new Color(200, 50, 50));
                iniciarMonitoramentoReal("/var/log/vm_auth.log");
            } else {
                isMonitoring = false;
                btnLiveMonitor.setText("Monitorar /var/log/vm_auth.log");
                btnLiveMonitor.setBackground(new Color(40, 160, 80));
                if (monitorThread != null) monitorThread.interrupt();
            }
        });
    }

    private void iniciarMonitoramentoReal(String filePath) {
        monitorThread = new Thread(() -> {

            java.nio.file.Path path = java.nio.file.Paths.get(filePath);

            try (BufferedReader reader = java.nio.file.Files.newBufferedReader(path, java.nio.charset.StandardCharsets.UTF_8)) {
                String line;

                System.out.println("[INFO] Carregando histórico e iniciando monitoramento ativo...");

                // Processa o histórico existente
                while ((line = reader.readLine()) != null) {
                    final String existingLine = line;
                    SwingUtilities.invokeLater(() -> processarLinhaDeLog(existingLine));
                }

                // Loop contínuo para novos eventos
                while (isMonitoring) {
                    line = reader.readLine();
                    if (line != null) {
                        final String finalLine = line;
                        SwingUtilities.invokeLater(() -> processarLinhaDeLog(finalLine));
                    } else {
                        Thread.sleep(300);
                    }
                }
            } catch (IOException e) {
                System.err.println("[ERRO DE LEITURA] Falha ao acessar o arquivo: " + e.getMessage());
            } catch (InterruptedException e) {
                System.out.println("[INFO] Monitoramento pausado.");
            }
        });
        monitorThread.start();
    }

    private void processarLinhaDeLog(String line) {
        LogEntry log = LogParserFactory.parseLine(line);
        if (log != null) {
            tableModel.addRow(new Object[]{
                    log.getTimestamp(),
                    log.getSourceIp(),
                    log.getLogLevel(),
                    log.getDetails()
            });
            siemEngine.processLog(log);
        }
    }

    private void carregarLogsSimulados() {
        tableModel.setRowCount(0);
        alertTextArea.setText("");
        String[] logsFromFile = {
                "May 29 21:00:15 ubuntu-srv sshd[12345]: Failed password for invalid user root from 198.51.100.42 port 49232 ssh2",
                "May 29 21:10:01 ubuntu-srv kernel: [UFW BLOCK] IN=eth0 OUT= SRC=203.0.113.5 DST=192.168.1.100 PROTO=TCP DPT=22"
        };
        for (String line : logsFromFile) {
            processarLinhaDeLog(line);
        }
    }

    private void redirecionarSystemOut() {
        PrintStream printStream = new PrintStream(new java.io.OutputStream() {
            @Override
            public void write(int b) {
                alertTextArea.append(String.valueOf((char) b));
                alertTextArea.setCaretPosition(alertTextArea.getDocument().getLength());
            }
        });
        System.setOut(printStream);
    }
}