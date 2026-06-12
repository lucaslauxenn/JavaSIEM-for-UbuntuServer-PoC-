package com.siem.factory;

import com.siem.models.*;
import java.time.ZonedDateTime;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class LogParserFactory {

    // Regex ultra-simplificadas e focadas apenas na extração dos dados brutos
    private static final Pattern SUDO_PATTERN = Pattern.compile("sudo:\\s+(\\S+)\\s+:\\s+TTY=.*USER=(\\S+)\\s+;\\s+COMMAND=(.+)");
    private static final Pattern SSHD_FAILED_PATTERN = Pattern.compile("sshd\\[\\d+\\]: Failed password for (?:invalid user )?(\\S+) from (\\S+)");
    private static final Pattern PAM_FAILED_PATTERN = Pattern.compile("(sshd|su):pam_unix\\(\\s*\\S+\\s*\\): authentication failure;.*user=(\\S+)");

    public static LogEntry parseLine(String rawLine) {
        if (rawLine == null || rawLine.trim().isEmpty()) return null;

        // Limpa espaços invisíveis ou duplicados nas pontas do log do syslog
        String cleanLine = rawLine.trim().replaceAll("\\s+", " ");
        LocalDateTime timestamp = parseUbuntuTimestamp(cleanLine);

        // -----------------------------------------------------------------
        // DIAGNÓSTICO: Ignora logs de fechamento de sessão ou CRON para não poluir
        // -----------------------------------------------------------------
        if (cleanLine.contains("session closed") || cleanLine.contains("CRON")) {
            return null;
        }

        System.out.println("\n[ANALISANDO LINHA]: " + cleanLine);

        // 1. CAPTURA DE COMANDOS SUDO
        if (cleanLine.contains("sudo:")) {
            Matcher matcher = SUDO_PATTERN.matcher(cleanLine);
            if (matcher.find()) {
                String targetUser = matcher.group(2);
                String command = matcher.group(3);
                System.out.println("  -> [MATCH SUDO] Usuário Alvo: " + targetUser + " | Comando: " + command);
                return new PrivilegeEscalationLog(timestamp, "127.0.0.1", "NOTICE", targetUser, command, true);
            } else {
                System.out.println("  -> [FALHA SUDO REGEX] A linha contém 'sudo:' mas o Regex falhou em extrair os dados.");
            }
        }

        // 2. CAPTURA DE SSHD DIRETO (Failed password for...)
        if (cleanLine.contains("Failed password for")) {
            Matcher matcher = SSHD_FAILED_PATTERN.matcher(cleanLine);
            if (matcher.find()) {
                String username = matcher.group(1);
                String sourceIp = matcher.group(2);
                System.out.println("  -> [MATCH SSHD] Usuário: " + username + " | IP: " + sourceIp);
                return new AuthenticationLog(timestamp, sourceIp, "WARN", username, false, "SSH-Password");
            } else {
                System.out.println("  -> [FALHA SSHD REGEX] A linha contém 'Failed password for' mas o Regex falhou.");
            }
        }

        // 3. CAPTURA DE FALHAS DO PAM (authentication failure;)
        if (cleanLine.contains("authentication failure;")) {
            // Remove espaços e parênteses colados para o Regex não quebrar
            String normalizedPam = cleanLine.replaceAll("\\s+", "").toLowerCase();

            // Verificação direta via String se o Regex falhar
            String username = "desconhecido";
            if (normalizedPam.contains("user=")) {
                username = normalizedPam.substring(normalizedPam.indexOf("user=") + 5);
            }

            String service = cleanLine.contains("sshd") ? "sshd" : "su";
            String sourceIp = cleanLine.contains("rhost=") ? extractIpFromPam(cleanLine) : "127.0.0.1 (VM Local)";

            System.out.println("  -> [MATCH PAM DIRETO] Serviço: " + service + " | Usuário: " + username + " | IP: " + sourceIp);
            return new AuthenticationLog(timestamp, sourceIp, "WARN", username, false, service.toUpperCase() + "-PAM");
        }

        System.out.println("  -> [LINHA IGNORADA] Sem regras correspondentes para este evento.");
        return null;
    }

    private static String extractIpFromPam(String line) {
        Pattern ipPattern = Pattern.compile("rhost=(\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3})");
        Matcher matcher = ipPattern.matcher(line);
        return matcher.find() ? matcher.group(1) : "10.0.2.2";
    }

    private static LocalDateTime parseUbuntuTimestamp(String line) {
        try {
            // Extrai a primeira palavra (o Timestamp ISO)
            String rawTimestamp = line.split(" ")[0];
            ZonedDateTime zdt = ZonedDateTime.parse(rawTimestamp, DateTimeFormatter.ISO_OFFSET_DATE_TIME);
            return zdt.toLocalDateTime();
        } catch (Exception e) {
            return LocalDateTime.now();
        }
    }
}