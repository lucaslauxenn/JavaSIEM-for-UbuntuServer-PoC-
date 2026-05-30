package com.siem.models;

import java.time.LocalDateTime;

public class FirewallLog extends LogEntry {
    private final int destinationPort;
    private final String protocol; 
    private final String action;   

    public FirewallLog(LocalDateTime timestamp, String sourceIp, String logLevel, 
                       int destinationPort, String protocol, String action) {
        super(timestamp, sourceIp, logLevel);
        this.destinationPort = destinationPort;
        this.protocol = protocol;
        this.action = action;
    }

    public int getDestinationPort() { return destinationPort; }
    public String getProtocol() { return protocol; }
    public String getAction() { return action; }

    @Override
    public String getDetails() {
        return String.format("Firewall %s traffic from %s over %s on Destination Port: %d", 
                action, getSourceIp(), protocol, destinationPort);
    }
}