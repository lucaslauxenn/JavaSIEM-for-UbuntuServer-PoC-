package com.siem.models;

import java.time.LocalDateTime;

public class PrivilegeEscalationLog extends LogEntry {
    private final String targetUser;  
    private final String command;     
    private final boolean wasAllowed; 

    public PrivilegeEscalationLog(LocalDateTime timestamp, String sourceIp, String logLevel, 
                                  String targetUser, String command, boolean wasAllowed) {
        super(timestamp, sourceIp, logLevel);
        this.targetUser = targetUser;
        this.command = command;
        this.wasAllowed = wasAllowed;
    }

    public String getTargetUser() { return targetUser; }
    public String getCommand() { return command; }
    public boolean getWasAllowed() { return wasAllowed; }

    @Override
    public String getDetails() {
        return String.format("Privilege escalation attempt to user '%s' executing command: [%s]. Authorized: %b", 
                targetUser, command, wasAllowed);
    }
}