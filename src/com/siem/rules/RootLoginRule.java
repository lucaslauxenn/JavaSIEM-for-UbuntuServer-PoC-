package com.siem.rules;

import com.siem.engine.DetectionRule;
import com.siem.models.LogEntry;
import com.siem.models.AuthenticationLog;

public class RootLoginRule implements DetectionRule {
    @Override
    public boolean evaluate(LogEntry entry) {
        if (entry instanceof AuthenticationLog) {
            AuthenticationLog authLog = (AuthenticationLog) entry;
            return "root".equals(authLog.getUsername()) && !authLog.isSuccess();
        }
        return false;
    }

    @Override public String getRuleName() { return "Unauthorized Root Login Attempt"; }
    @Override public String getSeverity() { return "HIGH"; }
}