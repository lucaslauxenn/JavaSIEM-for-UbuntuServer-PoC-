package com.siem.engine;

import com.siem.models.LogEntry;
import java.util.ArrayList;
import java.util.List;

public class SiemEngine {
    private final List<DetectionRule> rules = new ArrayList<>();

    public void registerRule(DetectionRule rule) {
        rules.add(rule);
    }

    public void processLog(LogEntry log) {
        for (DetectionRule rule : rules) {
            if (rule.evaluate(log)) {
                triggerAlert(rule, log);
            }
        }
    }

    private void triggerAlert(DetectionRule rule, LogEntry log) {
        System.out.printf("[ALERT - %s] %s triggered at %s. Source IP: %s. Details: %s%n",
                rule.getSeverity(), rule.getRuleName(), log.getTimestamp(), log.getSourceIp(), log.getDetails());
    }
}