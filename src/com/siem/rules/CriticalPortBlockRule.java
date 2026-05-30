package com.siem.rules;

import com.siem.engine.DetectionRule;
import com.siem.models.LogEntry;
import com.siem.models.FirewallLog;

public class CriticalPortBlockRule implements DetectionRule {
    @Override
    public boolean evaluate(LogEntry entry) {
        if (entry instanceof FirewallLog) {
            FirewallLog fwLog = (FirewallLog) entry;
            // Alert if firewall blocks connections targeted at sensitive administrative services
            return "BLOCK".equals(fwLog.getAction()) && 
                   (fwLog.getDestinationPort() == 22 || fwLog.getDestinationPort() == 8000);
        }
        return false;
    }

    @Override public String getRuleName() { return "Blocked Connection on Critical Management Port"; }
    @Override public String getSeverity() { return "MEDIUM"; }
}