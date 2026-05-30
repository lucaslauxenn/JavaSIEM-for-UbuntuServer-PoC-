package com.siem.models;

import java.time.LocalDateTime;

public class AuthenticationLog extends LogEntry {
    private final String username;
    private final boolean isSuccess;
    private final String authMethod;

    public AuthenticationLog(LocalDateTime timestamp, String sourceIp, String logLevel, 
                             String username, boolean isSuccess, String authMethod) {
        super(timestamp, sourceIp, logLevel);
        this.username = username;
        this.isSuccess = isSuccess;
        this.authMethod = authMethod;
    }

    public String getUsername() { return username; }
    public boolean isSuccess() { return isSuccess; }
    public String getAuthMethod() { return authMethod; }

    @Override
    public String getDetails() {
        return String.format("Authentication attempt for user '%s' via %s. Result: %s", 
                username, authMethod, isSuccess ? "SUCCESS" : "FAILED");
    }
}