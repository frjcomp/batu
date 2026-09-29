import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ToolType;
import burp.api.montoya.http.handler.HttpHandler;
import burp.api.montoya.http.handler.HttpRequestToBeSent;
import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.api.montoya.http.handler.RequestToBeSentAction;
import burp.api.montoya.http.handler.ResponseReceivedAction;
import burp.api.montoya.http.message.requests.HttpRequest;

import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.SwingUtilities;
import javax.swing.border.EmptyBorder;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.Font;
import java.awt.Toolkit;
import java.awt.datatransfer.StringSelection;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.Locale;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class Extension implements BurpExtension {
    private static final String TOKEN_PLACEHOLDER = "<@batu_token@>";
    private static final Pattern OIDC_TOKEN_PATTERN = Pattern.compile("(?i)/protocol/openid-connect/token(?:\\?|$)");
    private static final Pattern ACCESS_TOKEN_JSON_PATTERN = Pattern.compile("\\\"access_token\\\"\\s*:\\s*\\\"([^\\\"]+)\\\"");
    private static final DateTimeFormatter TIMESTAMP_FORMATTER = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss.SSS")
            .withLocale(Locale.US)
            .withZone(ZoneId.systemDefault());

    private final AtomicBoolean enabled = new AtomicBoolean(true);
    private final Object uiLock = new Object();

    private MontoyaApi montoyaApi;
    private JTextArea logArea;
    private JLabel statusLabel;
    private JTextField jwtField;
    private volatile String currentJwt = "";

    @Override
    public void initialize(MontoyaApi montoyaApi) {
        this.montoyaApi = montoyaApi;
        montoyaApi.extension().setName("batu");

        mountUi();
        montoyaApi.http().registerHttpHandler(new BatuHttpHandler());
        logDebug("batu extension initialized");
    }

    private void mountUi() {
        JPanel panel = new JPanel(new BorderLayout(10, 10));
        panel.setBorder(new EmptyBorder(10, 10, 10, 10));

        JPanel headerPanel = new JPanel(new BorderLayout(10, 8));
        headerPanel.setBorder(BorderFactory.createTitledBorder("batu"));

        JPanel toolbar = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 4));
        JCheckBox enabledCheckbox = new JCheckBox("Enabled");
        enabledCheckbox.setSelected(true);
        enabledCheckbox.addActionListener(event -> {
            enabled.set(enabledCheckbox.isSelected());
            logDebug("extension " + (enabled.get() ? "enabled" : "disabled"));
            updateStatusLabel();
        });

        JButton clearButton = new JButton("Clear logs");
        clearButton.addActionListener(event -> {
            synchronized (uiLock) {
                if (logArea != null) {
                    logArea.setText("[" + now() + "] INFO batu logs cleared\n");
                }
            }
        });

        JButton copyButton = new JButton("Copy JWT");
        copyButton.addActionListener(event -> {
            if (currentJwt != null && !currentJwt.isBlank()) {
                Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new java.awt.datatransfer.StringSelection(currentJwt), null);
                logDebug("copied current JWT to clipboard");
            }
        });

        statusLabel = new JLabel("Status: ready");
        statusLabel.setFont(statusLabel.getFont().deriveFont(Font.BOLD));
        statusLabel.setForeground(new Color(0x2e7d32));
        toolbar.add(enabledCheckbox);
        toolbar.add(clearButton);
        toolbar.add(copyButton);
        toolbar.add(statusLabel);

        jwtField = new JTextField();
        jwtField.setEditable(false);
        jwtField.setText("<no JWT captured>");
        jwtField.setPreferredSize(new Dimension(600, 28));
        jwtField.setToolTipText("Copyable current JWT value");

        headerPanel.add(toolbar, BorderLayout.NORTH);
        headerPanel.add(jwtField, BorderLayout.SOUTH);

        logArea = new JTextArea(20, 90);
        logArea.setEditable(false);
        logArea.setLineWrap(true);
        logArea.setWrapStyleWord(true);
        logArea.setFont(new java.awt.Font(java.awt.Font.MONOSPACED, java.awt.Font.PLAIN, 12));
        logArea.setText("[" + now() + "] DEBUG batu ready. Waiting for new access_token responses...\n");

        JScrollPane scrollPane = new JScrollPane(logArea);
        scrollPane.setBorder(BorderFactory.createTitledBorder("batu logs"));

        panel.add(headerPanel, BorderLayout.NORTH);
        panel.add(scrollPane, BorderLayout.CENTER);

        montoyaApi.userInterface().registerSuiteTab("batu", panel);
    }

    private void updateStatusLabel() {
        SwingUtilities.invokeLater(() -> {
            if (statusLabel == null) {
                return;
            }

            if (currentJwt.isEmpty()) {
                statusLabel.setText("Status: no JWT captured");
                statusLabel.setForeground(new Color(0x9a5b00));
                if (jwtField != null) {
                    jwtField.setText("<no JWT captured>");
                }
            } else {
                statusLabel.setText("Status: JWT active");
                statusLabel.setForeground(new Color(0x2e7d32));
                if (jwtField != null) {
                    jwtField.setText(currentJwt);
                }
            }
        });
    }

    private void logInfo(String message) {
        String entry = "[" + now() + "] INFO " + message;
        appendLog(entry);
        if (montoyaApi != null) {
            montoyaApi.logging().raiseInfoEvent("batu: " + message);
        }
    }

    private void logDebug(String message) {
        String entry = "[" + now() + "] DEBUG " + message;
        appendLog(entry);
        if (montoyaApi != null) {
            montoyaApi.logging().raiseDebugEvent("batu: " + message);
        }
    }

    private void appendLog(String entry) {
        SwingUtilities.invokeLater(() -> {
            synchronized (uiLock) {
                if (logArea != null) {
                    logArea.append(entry + "\n");
                    logArea.setCaretPosition(logArea.getDocument().getLength());
                }
            }
        });
    }

    private HttpRequest refreshContentLength(HttpRequest request) {
        try {
            int bodyLength = request.body() == null ? 0 : request.body().length();
            return request.withUpdatedHeader("Content-Length", String.valueOf(bodyLength));
        } catch (Exception ignored) {
            return request;
        }
    }

    private String now() {
        return TIMESTAMP_FORMATTER.format(Instant.now());
    }

    private static String extractAccessToken(String body) {
        if (body == null || body.isBlank()) {
            return "";
        }

        Matcher matcher = ACCESS_TOKEN_JSON_PATTERN.matcher(body);
        if (matcher.find()) {
            return matcher.group(1);
        }
        return "";
    }

    private boolean shouldProcessRequest(HttpRequestToBeSent request) {
        if (request == null || request.toolSource() == null) {
            return false;
        }

        return request.toolSource().isFromTool(ToolType.REPEATER, ToolType.INTRUDER, ToolType.SCANNER);
    }

    private class BatuHttpHandler implements HttpHandler {
        @Override
        public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent requestToBeSent) {
            if (!enabled.get()) {
                return RequestToBeSentAction.continueWith(requestToBeSent);
            }

            if (!shouldProcessRequest(requestToBeSent)) {
                return RequestToBeSentAction.continueWith(requestToBeSent);
            }

            if (currentJwt.isEmpty()) {
                logDebug("detected placeholder in Repeater/Intruder/Scanner request but current JWT is empty; nothing replaced");
                return RequestToBeSentAction.continueWith(requestToBeSent);
            }

            HttpRequest updatedRequest = requestToBeSent;
            boolean replaced = false;

            for (var header : requestToBeSent.headers()) {
                String headerValue = header.value();
                if (headerValue != null && headerValue.contains(TOKEN_PLACEHOLDER)) {
                    String updatedHeaderValue = headerValue.replace(TOKEN_PLACEHOLDER, currentJwt);
                    updatedRequest = updatedRequest.withUpdatedHeader(header.name(), updatedHeaderValue);
                    replaced = true;
                }
            }

            String body = updatedRequest.bodyToString();
            if (body != null && !body.isEmpty() && body.contains(TOKEN_PLACEHOLDER)) {
                String replacedBody = body.replace(TOKEN_PLACEHOLDER, currentJwt);
                updatedRequest = updatedRequest.withBody(replacedBody);
                updatedRequest = refreshContentLength(updatedRequest);
                replaced = true;
            }

            if (!replaced) {
                return RequestToBeSentAction.continueWith(requestToBeSent);
            }

            int beforeLength = requestToBeSent.body() == null ? 0 : requestToBeSent.body().length();
            int afterLength = updatedRequest.body() == null ? 0 : updatedRequest.body().length();
            logDebug("replaced token placeholder in outgoing request: " + updatedRequest.url() + " bodyLen " + beforeLength + "->" + afterLength);
            return RequestToBeSentAction.continueWith(updatedRequest);
        }

        @Override
        public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived responseReceived) {
            try {
                if (responseReceived == null || responseReceived.initiatingRequest() == null) {
                    return ResponseReceivedAction.continueWith(responseReceived);
                }

                String requestUrl = responseReceived.initiatingRequest().url();
                if (requestUrl == null || !OIDC_TOKEN_PATTERN.matcher(requestUrl).find()) {
                    return ResponseReceivedAction.continueWith(responseReceived);
                }

                String responseBody = responseReceived.bodyToString();
                String newJwt = extractAccessToken(responseBody);
                if (newJwt == null || newJwt.isBlank()) {
                    return ResponseReceivedAction.continueWith(responseReceived);
                }

                if (newJwt.equals(currentJwt)) {
                    return ResponseReceivedAction.continueWith(responseReceived);
                }

                currentJwt = newJwt;
                updateStatusLabel();
                logInfo("new access_token detected at " + now() + " value=" + currentJwt);
                montoyaApi.logging().logToOutput("batu: new jwt stored for future requests at " + now());
            } catch (Exception exception) {
                logDebug("failed to process token response: " + exception.getMessage());
            }

            return ResponseReceivedAction.continueWith(responseReceived);
        }
    }
}
