package com.siem.engine;

import com.siem.models.LogEntry;

public interface DetectionRule {
    boolean evaluate(LogEntry entry);
    String getRuleName();
    String getSeverity();
}