import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ssl.HttpsURLConnection;
import java.io.*;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.cert.CertificateException;
import java.text.SimpleDateFormat;
import java.util.*;

public class CertManagerClient {

    static final String TASK_NAME = "CertManagerClient";
    static String BASE_DIR;
    static String CONFIG_PATH;
    static String LOG_DIR;

    public static void main(String[] args) {
        try {
            String jarPath = getJarPath();
            BASE_DIR = new File(jarPath).getParent();
        } catch (Exception e) {
            BASE_DIR = System.getProperty("user.dir");
        }
        CONFIG_PATH = BASE_DIR + File.separator + "conf.json";
        LOG_DIR = BASE_DIR + File.separator + "logs";

        setupLogging();
        log("INFO", "CertManager Client v1.0 (Java) started");

        JsonObject config = loadConfig();
        if (config == null) return;

        if (!isTaskInstalled()) {
            log("INFO", "Scheduled task not installed. Installing...");
            installTask();
            return;
        }

        int renewDays = config.getInt("certRenewDays", 5);
        List<JsonObject> domains = config.getArray("domains");
        List<JsonObject> toRenew = new ArrayList<>();

        for (JsonObject domain : domains) {
            if (shouldRenew(domain, renewDays)) {
                toRenew.add(domain);
            }
        }

        if (toRenew.isEmpty()) {
            log("INFO", "All certificates are valid, no renewal needed");
            return;
        }

        StringBuilder names = new StringBuilder();
        for (JsonObject d : toRenew) {
            if (names.length() > 0) names.append(", ");
            names.append(d.getString("name"));
        }
        log("INFO", "Certificates to renew: " + names);

        try {
            String serverUrl = config.getString("serverUrl");
            String key = config.getString("key");
            String salt = config.getString("salt");

            JsonObject result = callApi(serverUrl, key, salt, toRenew);
            List<JsonObject> certList = result.getArray("data");
            if (certList.isEmpty()) {
                log("ERROR", "No certificate data returned from server");
                return;
            }

            Map<String, JsonObject> certMap = new HashMap<>();
            for (JsonObject ci : certList) {
                certMap.put(ci.getString("domain"), ci);
            }

            for (JsonObject domain : toRenew) {
                String name = domain.getString("name");
                JsonObject certInfo = certMap.get(name);
                if (certInfo == null) {
                    log("WARN", "No data returned for " + name + ", skipping");
                    continue;
                }
                saveCert(domain, certInfo);
            }

            reloadNginx(config);
            log("INFO", "Certificate renewal completed successfully");

        } catch (Exception e) {
            log("ERROR", "Failed to download certificates: " + e.getMessage());
        }
    }

    static boolean shouldRenew(JsonObject domain, int renewDays) {
        String path = domain.getString("fullchainPath");
        File f = new File(path);
        if (!f.exists()) {
            log("INFO", "Certificate file not found: " + path + ", will download");
            return true;
        }
        try {
            String pem = new String(Files.readAllBytes(f.toPath()), StandardCharsets.UTF_8);
            int start = pem.indexOf("-----BEGIN CERTIFICATE-----");
            int end = pem.indexOf("-----END CERTIFICATE-----");
            if (start < 0 || end <= start) {
                log("WARN", "No PEM certificate found in " + path + ", will download");
                return true;
            }
            String firstCert = pem.substring(start, end + "-----END CERTIFICATE-----".length());
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            X509Certificate cert = (X509Certificate) cf.generateCertificate(
                new ByteArrayInputStream(firstCert.getBytes(StandardCharsets.UTF_8)));
            long daysLeft = (cert.getNotAfter().getTime() - System.currentTimeMillis()) / (1000L * 86400);
            log("INFO", "Certificate " + domain.getString("name") + " expires in " + daysLeft + " days");
            if (daysLeft <= renewDays) {
                log("INFO", domain.getString("name") + " expires in " + daysLeft + " days, will renew");
                return true;
            }
            return false;
        } catch (Exception e) {
            log("WARN", "Failed to parse certificate: " + e.getMessage() + ", will download");
            return true;
        }
    }

    static JsonObject callApi(String serverUrl, String key, String salt, List<JsonObject> domains) throws Exception {
        String timestamp = String.valueOf(System.currentTimeMillis());
        // 不带 sign 的 JSON body，用于签名
        StringBuilder body = new StringBuilder();
        body.append("{\"key\":\"").append(escapeJson(key))
            .append("\",\"timestamp\":\"").append(timestamp)
            .append("\",\"sign\":\"\"")
            .append(",\"domains\":[");
        for (int i = 0; i < domains.size(); i++) {
            if (i > 0) body.append(",");
            body.append("\"").append(escapeJson(domains.get(i).getString("name"))).append("\"");
        }
        body.append("]}");

        String signData = timestamp + body.toString();
        String sign = hmacSha256(salt, signData);
        // 用真实 sign 替换占位
        String payload = body.toString().replace("\"sign\":\"\"", "\"sign\":\"" + sign + "\"");

        byte[] bodyBytes = payload.getBytes(StandardCharsets.UTF_8);
        URL url = new URL(serverUrl.endsWith("/") ? serverUrl + "cert/download" : serverUrl + "/cert/download");
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod("POST");
        conn.setRequestProperty("Content-Type", "application/json");
        conn.setDoOutput(true);
        conn.setConnectTimeout(15000);
        conn.setReadTimeout(30000);
        try (OutputStream os = conn.getOutputStream()) {
            os.write(bodyBytes);
        }

        int status = conn.getResponseCode();
        String respBody;
        try (InputStream is = (status >= 400) ? conn.getErrorStream() : conn.getInputStream()) {
            respBody = new String(readAll(is), StandardCharsets.UTF_8);
        }
        conn.disconnect();

        if (status >= 400) {
            throw new RuntimeException("Server returned " + status + ": " + respBody);
        }

        return parseJson(respBody);
    }

    static void saveCert(JsonObject domain, JsonObject certInfo) throws IOException {
        Path fullchainPath = Paths.get(domain.getString("fullchainPath"));
        Path privkeyPath = Paths.get(domain.getString("privkeyPath"));
        Files.createDirectories(fullchainPath.getParent());
        Files.createDirectories(privkeyPath.getParent());
        Files.write(fullchainPath, certInfo.getString("fullchainPem").getBytes(StandardCharsets.UTF_8));
        Files.write(privkeyPath, certInfo.getString("privkeyPem").getBytes(StandardCharsets.UTF_8));
        log("INFO", "Saved certificate for " + domain.getString("name"));
    }

    static void reloadNginx(JsonObject config) {
        String nginxPath = config.getString("nginxPath", "");
        String reloadCmd = config.getString("nginxReloadCmd", "nginx -s reload");

        if (nginxPath.isEmpty()) {
            String detected = autoDetectNginx();
            if (detected != null) {
                nginxPath = detected;
                log("INFO", "Auto-detected nginx path: " + nginxPath);
            } else {
                log("WARN", "nginx path not configured and auto-detection failed");
            }
        }

        if (!nginxPath.isEmpty()) {
            File nginxExe = new File(nginxPath);
            File nginxDir = nginxExe.getParentFile();

            // 先检查 nginx 是否在运行
            boolean running = false;
            try {
                Process p = Runtime.getRuntime().exec(
                    "tasklist /fi \"imagename eq nginx.exe\" /nh");
                BufferedReader r = new BufferedReader(new InputStreamReader(p.getInputStream(), "GBK"));
                String line;
                while ((line = r.readLine()) != null) {
                    if (line.contains("nginx.exe")) { running = true; break; }
                }
            } catch (Exception ignored) {}

            try {
                ProcessBuilder pb;
                if (running) {
                    pb = new ProcessBuilder(nginxExe.getPath(), "-s", "reload");
                    log("INFO", "Nginx is running, reloading");
                } else {
                    pb = new ProcessBuilder(nginxExe.getPath());
                    log("INFO", "Nginx not running, starting");
                }
                pb.directory(nginxDir);
                Process p = pb.start();
                p.waitFor();
                if (p.exitValue() == 0) {
                    log("INFO", "Nginx operation completed successfully");
                } else {
                    log("WARN", "Nginx returned exit code " + p.exitValue());
                }
            } catch (Exception e) {
                log("ERROR", "Failed to run nginx: " + e.getMessage());
            }
        } else {
            log("WARN", "No nginx path configured, skipping nginx reload");
        }
    }

    static String autoDetectNginx() {
        try {
            Process p = Runtime.getRuntime().exec(
                "wmic process where \"name='nginx.exe'\" get executablepath");
            BufferedReader r = new BufferedReader(new InputStreamReader(p.getInputStream()));
            String line;
            while ((line = r.readLine()) != null) {
                line = line.trim();
                if (line.toLowerCase().endsWith("nginx.exe")) return line;
            }
        } catch (Exception ignored) {}
        return null;
    }

    static boolean isTaskInstalled() {
        String sysRoot = System.getenv("SystemRoot");
        if (sysRoot == null) sysRoot = "C:\\Windows";
        File f1 = new File(sysRoot + "\\System32\\Tasks\\" + TASK_NAME);
        if (f1.exists()) return true;
        File f2 = new File(sysRoot + "\\Sysnative\\Tasks\\" + TASK_NAME);
        if (f2.exists()) return true;
        return false;
    }

    static void installTask() {
        try {
            String jarPath = getJarPath();
            String exePath = "java -jar \"" + jarPath + "\"";

            int hour = 1 + new Random().nextInt(3);
            int minute = new Random().nextInt(60);
            String timeStr = String.format("%02d:%02d", hour, minute);

            String cmd = "schtasks /create /tn \"" + TASK_NAME + "\" /tr \""
                + exePath + "\" /sc daily /st " + timeStr + " /f";
            log("INFO", "Creating scheduled task...");
            Process p = Runtime.getRuntime().exec(cmd);
            p.waitFor();
            if (p.exitValue() == 0) {
                log("INFO", "Scheduled task '" + TASK_NAME + "' created, will run daily at " + timeStr);
            } else {
                log("ERROR", "Failed to create scheduled task");
            }
        } catch (Exception e) {
            log("ERROR", "Failed to install task: " + e.getMessage());
        }
    }

    static String getJarPath() throws Exception {
        String path = CertManagerClient.class.getProtectionDomain()
            .getCodeSource().getLocation().toURI().getPath();
        if (path.startsWith("/") && path.length() > 2 && path.charAt(2) == ':')
            path = path.substring(1);
        return path;
    }

    static String hmacSha256(String key, String data) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(key.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
        byte[] hash = mac.doFinal(data.getBytes(StandardCharsets.UTF_8));
        StringBuilder hex = new StringBuilder();
        for (byte b : hash) hex.append(String.format("%02x", b & 0xff));
        return hex.toString();
    }

    static String escapeJson(String s) {
        return s.replace("\\", "\\\\").replace("\"", "\\\"")
            .replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t");
    }

    // ───── JSON 工具 ─────

    static JsonObject parseJson(String json) {
        return new JsonParser(json).parseObject();
    }

    static class JsonParser {
        final String s;
        int pos;

        JsonParser(String s) { this.s = s.trim(); }

        JsonObject parseObject() {
            JsonObject obj = new JsonObject();
            if (s.charAt(pos) == '{') pos++;
            skipWs();
            if (pos < s.length() && s.charAt(pos) == '}') { pos++; return obj; }
            while (pos < s.length()) {
                skipWs();
                String key = parseString();
                skipWs();
                if (pos < s.length() && s.charAt(pos) == ':') pos++;
                skipWs();
                Object val = parseValue();
                obj.put(key, val);
                skipWs();
                if (pos < s.length() && s.charAt(pos) == ',') pos++;
                skipWs();
                if (pos < s.length() && s.charAt(pos) == '}') { pos++; break; }
            }
            return obj;
        }

        List<Object> parseArray() {
            List<Object> list = new ArrayList<>();
            if (s.charAt(pos) == '[') pos++;
            skipWs();
            if (pos < s.length() && s.charAt(pos) == ']') { pos++; return list; }
            while (pos < s.length()) {
                skipWs();
                list.add(parseValue());
                skipWs();
                if (pos < s.length() && s.charAt(pos) == ',') pos++;
                skipWs();
                if (pos < s.length() && s.charAt(pos) == ']') { pos++; break; }
            }
            return list;
        }

        Object parseValue() {
            skipWs();
            if (pos >= s.length()) return null;
            char c = s.charAt(pos);
            if (c == '"') return parseString();
            if (c == '{') return parseObject();
            if (c == '[') return parseArray();
            if (c == 't' || c == 'f') return Boolean.parseBoolean(parseRaw());
            if (c == 'n') { parseRaw(); return null; }
            return Double.parseDouble(parseRaw());
        }

        String parseString() {
            if (s.charAt(pos) == '"') pos++;
            StringBuilder sb = new StringBuilder();
            while (pos < s.length()) {
                char c = s.charAt(pos++);
                if (c == '"') break;
                if (c == '\\') {
                    if (pos < s.length()) {
                        char next = s.charAt(pos++);
                        switch (next) {
                            case '"': sb.append('"'); break;
                            case '\\': sb.append('\\'); break;
                            case '/': sb.append('/'); break;
                            case 'b': sb.append('\b'); break;
                            case 'f': sb.append('\f'); break;
                            case 'n': sb.append('\n'); break;
                            case 'r': sb.append('\r'); break;
                            case 't': sb.append('\t'); break;
                            case 'u':
                                if (pos + 4 <= s.length()) {
                                    sb.append((char) Integer.parseInt(s.substring(pos, pos + 4), 16));
                                    pos += 4;
                                }
                                break;
                        }
                    }
                } else {
                    sb.append(c);
                }
            }
            return sb.toString();
        }

        String parseRaw() {
            int start = pos;
            while (pos < s.length() && ",:}[]{ \t\n\r".indexOf(s.charAt(pos)) < 0) pos++;
            return s.substring(start, pos);
        }

        void skipWs() {
            while (pos < s.length() && " \t\n\r".indexOf(s.charAt(pos)) >= 0) pos++;
        }
    }

    static class JsonObject {
        final LinkedHashMap<String, Object> map = new LinkedHashMap<>();

        void put(String key, Object val) { map.put(key, val); }

        String getString(String key) { Object v = map.get(key); return v instanceof String ? (String) v : ""; }
        String getString(String key, String def) { Object v = map.get(key); return v instanceof String ? (String) v : def; }
        int getInt(String key, int def) {
            Object v = map.get(key);
            if (v instanceof Double) return ((Double) v).intValue();
            return def;
        }
        JsonObject getObject(String key) {
            Object v = map.get(key);
            return v instanceof JsonObject ? (JsonObject) v : null;
        }
        List<JsonObject> getArray(String key) {
            Object v = map.get(key);
            if (v instanceof List) {
                List<JsonObject> result = new ArrayList<>();
                for (Object item : (List<?>) v) {
                    if (item instanceof JsonObject) result.add((JsonObject) item);
                }
                return result;
            }
            return Collections.emptyList();
        }
    }

    // ───── 配置加载 ─────

    static JsonObject loadConfig() {
        File f = new File(CONFIG_PATH);
        if (!f.exists()) {
            System.err.println("配置文件不存在，正在生成示例配置...");
            generateExampleConfig();
            return null;
        }
        try {
            String json = new String(Files.readAllBytes(f.toPath()), StandardCharsets.UTF_8);
            JsonObject cfg = parseJson(json);
            String[] required = {"serverUrl", "key", "domains"};
            for (String r : required) {
                if (!cfg.map.containsKey(r) || (r.equals("domains") && cfg.getArray(r).isEmpty())) {
                    System.err.println("配置缺少必要字段: " + r);
                    generateExampleConfig();
                    return null;
                }
            }
            return cfg;
        } catch (Exception e) {
            System.err.println("读取配置文件失败: " + e.getMessage());
            generateExampleConfig();
            return null;
        }
    }

    static void generateExampleConfig() {
        String json =
            "{\n" +
            "  \"serverUrl\": \"http://127.0.0.1:15555\",\n" +
            "  \"key\": \"your-client-key\",\n" +
            "  \"salt\": \"your-client-salt\",\n" +
            "  \"nginxPath\": \"\",\n" +
            "  \"nginxReloadCmd\": \"nginx -s reload\",\n" +
            "  \"certRenewDays\": 5,\n" +
            "  \"domains\": [\n" +
            "    {\n" +
            "      \"name\": \"example.com\",\n" +
            "      \"fullchainPath\": \"C:/nginx/ssl/example.com/fullchain.pem\",\n" +
            "      \"privkeyPath\": \"C:/nginx/ssl/example.com/privkey.pem\"\n" +
            "    }\n" +
            "  ]\n" +
            "}\n";
        try {
            Files.write(Paths.get(CONFIG_PATH), json.getBytes(StandardCharsets.UTF_8));
            System.err.println("示例配置文件已创建: " + CONFIG_PATH);
        } catch (IOException e) {
            System.err.println("写入示例配置失败: " + e.getMessage());
        }
    }

    // ───── 日志 ─────

    static String logFile;

    static void setupLogging() {
        SimpleDateFormat sdf = new SimpleDateFormat("yyyy/MM");
        SimpleDateFormat fileSdf = new SimpleDateFormat("yyyyMMdd");
        Date now = new Date();
        String logDir = LOG_DIR + File.separator + sdf.format(now);
        new File(logDir).mkdirs();
        logFile = logDir + File.separator + "certmanager_" + fileSdf.format(now) + ".log";
    }

    static void log(String level, String msg) {
        SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
        String line = "[" + sdf.format(new Date()) + "] [" + level + "] " + msg;
        System.out.println(line);
        if (logFile != null) {
            try (FileWriter fw = new FileWriter(logFile, true)) {
                fw.write(line + System.lineSeparator());
            } catch (IOException ignored) {}
        }
    }

    static byte[] readAll(InputStream is) throws IOException {
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        byte[] tmp = new byte[8192];
        int n;
        while ((n = is.read(tmp)) > 0) buf.write(tmp, 0, n);
        return buf.toByteArray();
    }
}
