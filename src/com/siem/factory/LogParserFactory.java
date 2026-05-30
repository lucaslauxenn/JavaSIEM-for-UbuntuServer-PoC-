package com.siem.factory;

import com.siem.models.*;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class LogParserFactory {

    private static final Pattern SSH_PATTERN = Pattern.compile(
        "(\\w{3}\\s+\\d+\\s+\\d+:\\d+:\\d+).*sshd\\[\\d+\\]: (Failed|Accepted) password for (?:invalid user )?(\\S+) from (\\S+)"
    );

    private static final Pattern SUDO_PATTERN = Pattern.compile(
        "(\\w{3}\\s+\\d+\\s+\\d+:\\d+:\\d+).*sudo:\\s+(\\S+) : .*USER=(\\S+) ; COMMAND=(.+)"
    );

    private static final Pattern UFW_PATTERN = Pattern.compile(
        "(\\w{3}\\s+\\d+\\s+\\d+:\\d+:\\d+).*\\s+\\[UFW (BLOCK|ALLOW)\\].*SRC=(\\S+).*PROTO=(\\S+).*DPT=(\\d+)"
    );

    public static LogEntry parseLine(String rawLine) {
        Matcher sshMatcher = SSH_PATTERN.matcher(rawLine);
        if (sshMatcher.find()) {
            LocalDateTime timestamp = parseUbuntuTimestamp(sshMatcher.group(1));
            boolean isSuccess = "Accepted".equals(sshMatcher.group(2));
            String username = sshMatcher.group(3);
            String sourceIp = sshMatcher.group(4);
            String logLevel = isSuccess ? "INFO" : "WARN";
            return new AuthenticationLog(timestamp, sourceIp, logLevel, username, isSuccess, "SSH-Password");
        }

        Matcher sudoMatcher = SUDO_PATTERN.matcher(rawLine);
        if (sudoMatcher.find()) {
            LocalDateTime timestamp = parseUbuntuTimestamp(sudoMatcher.group(1));
            String targetUser = sudoMatcher.group(3);
            String command = sudoMatcher.group(4);
            return new PrivilegeEscalationLog(timestamp, "127.0.0.1", "NOTICE", targetUser, command, true);
        }

        Matcher ufwMatcher = UFW_PATTERN.matcher(rawLine);
        if (ufwMatcher.find()) {
            LocalDateTime timestamp = parseUbuntuTimestamp(ufwMatcher.group(1));
            String action = ufwMatcher.group(2); 
            String sourceIp = ufwMatcher.group(3);
            String protocol = ufwMatcher.group(4);
            int destPort = Integer.parseInt(ufwMatcher.group(5));
            String logLevel = "BLOCK".equals(action) ? "WARN" : "INFO";
            return new FirewallLog(timestamp, sourceIp, logLevel, destPort, protocol, action);
        }

        return null; 
    }

    private static LocalDateTime parseUbuntuTimestamp(String rawTimestamp) {
        int currentYear = LocalDateTime.now().getYear();
        String datedString = currentYear + " " + rawTimestamp;

        // Using square brackets [] in the pattern makes sections optional.
        // This safely matches BOTH "May 22" (one space) and "May  5" (two spaces).
        DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy MMM[ ]d HH:mm:ss");

        return LocalDateTime.parse(datedString, formatter);
    }
}