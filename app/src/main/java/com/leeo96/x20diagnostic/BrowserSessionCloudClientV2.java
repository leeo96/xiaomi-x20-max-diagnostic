package com.leeo96.x20diagnostic;

import android.util.Base64;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.net.CookieHandler;
import java.net.CookieManager;
import java.net.CookiePolicy;
import java.net.HttpCookie;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * Browser-session Xiaomi Cloud client, revision 2.
 *
 * It upgrades the already-authenticated Xiaomi Account browser session to the
 * xiaomiio service session, then tries two independent device-list protocols:
 *  1) current RC4-encrypted Xiaomi Cloud API used by modern integrations;
 *  2) legacy HMAC /home/device_list API as a compatibility fallback.
 *
 * No account password reaches this class.
 */
public final class BrowserSessionCloudClientV2 {
    private static final String[] SERVERS = {"sg", "de", "us", "i2", "ru", "tw", "cn", "in"};
    private static final SecureRandom RNG = new SecureRandom();
    private static final String USER_AGENT = "X20Diagnostic-Android APP/com.xiaomi.mihome APPV/10.5.201";
    private static final String DEVICE_LIST_DATA =
            "{\"getVirtualModel\":true,\"getHuamiDevices\":1,\"get_split_device\":false,\"support_smart_home\":true}";

    private final CookieManager cookies = new CookieManager(null, CookiePolicy.ACCEPT_ALL);
    private String ssecurity;
    private String userId;
    private String serviceToken;

    public BrowserSessionCloudClientV2() {
        CookieHandler.setDefault(cookies);
    }

    public JSONObject fetchFromBrowserSession(String accountCookieHeader, String stsCookieHeader) throws Exception {
        if (accountCookieHeader == null || accountCookieHeader.trim().isEmpty()) {
            throw new IllegalStateException("Nenhuma sessão Xiaomi encontrada. Abra o login oficial e entre na conta primeiro.");
        }

        importCookieHeader(accountCookieHeader, ".xiaomi.com");
        if (stsCookieHeader != null && !stsCookieHeader.trim().isEmpty()) {
            importCookieHeader(stsCookieHeader, ".api.io.mi.com");
            importCookieHeader(stsCookieHeader, ".io.mi.com");
        }

        Map<String, String> headers = new LinkedHashMap<>();
        headers.put("Content-Type", "application/x-www-form-urlencoded");
        headers.put("Cookie", accountCookieHeader);

        HttpResult login = requestGet(
                "https://account.xiaomi.com/pass/serviceLogin?sid=xiaomiio&_json=true",
                headers, 10000, 10000);
        if (login.code != 200) {
            throw new IllegalStateException("Conta Xiaomi retornou HTTP " + login.code + " ao validar a sessão");
        }

        JSONObject auth = parseXiaomiJson(login.text);
        ssecurity = auth.optString("ssecurity", "");
        userId = stringOrNull(auth.opt("userId"));
        String location = auth.optString("location", "");
        if (ssecurity.isEmpty() || userId == null || location.isEmpty()) {
            throw new IllegalStateException("A sessão do navegador não foi convertida em sessão xiaomiio.");
        }

        requestGet(location, null, 10000, 12000);
        serviceToken = findCookie("serviceToken");
        if (serviceToken == null || serviceToken.isEmpty()) {
            throw new IllegalStateException("Login confirmado, mas a Xiaomi não entregou o serviceToken xiaomiio");
        }

        return fetchDeviceLists();
    }

    private JSONObject fetchDeviceLists() throws Exception {
        JSONArray devices = new JSONArray();
        JSONArray servers = new JSONArray();
        Set<String> seen = new HashSet<>();
        boolean foundTarget = false;

        for (String server : SERVERS) {
            JSONObject status = new JSONObject();
            status.put("server", server);
            int before = devices.length();

            // Modern RC4-encrypted API path used by current Xiaomi MIoT integrations.
            try {
                JSONObject response = rc4EncryptedCall(server, "home/device_list", DEVICE_LIST_DATA);
                int code = response.optInt("code", Integer.MIN_VALUE);
                status.put("rc4Code", code);
                status.put("rc4Message", response.optString("message", response.optString("description", "")));
                JSONArray list = extractList(response);
                status.put("rc4Devices", list == null ? 0 : list.length());
                if (code == 0 && list != null) {
                    foundTarget |= addDevices(server, list, devices, seen);
                }
            } catch (Exception ex) {
                status.put("rc4Error", safeMessage(ex));
            }

            // Compatibility fallback: old signed /home/device_list request.
            if (!foundTarget && devices.length() == before) {
                try {
                    JSONObject response = legacyDeviceList(server);
                    int code = response.optInt("code", Integer.MIN_VALUE);
                    status.put("legacyCode", code);
                    status.put("legacyMessage", response.optString("message", response.optString("description", "")));
                    JSONArray list = extractList(response);
                    status.put("legacyDevices", list == null ? 0 : list.length());
                    if (code == 0 && list != null) {
                        foundTarget |= addDevices(server, list, devices, seen);
                    }
                } catch (Exception ex) {
                    status.put("legacyError", safeMessage(ex));
                }
            }

            status.put("added", devices.length() - before);
            servers.put(status);
            if (foundTarget) break;
        }

        if (devices.length() == 0) {
            JSONObject err = new JSONObject();
            err.put("ok", false);
            err.put("type", "CloudDeviceListEmptyV2");
            err.put("error", "Login xiaomiio confirmado, mas nenhum dispositivo veio da Cloud. " + summarizeServers(servers));
            err.put("servers", servers);
            return err;
        }

        JSONObject out = new JSONObject();
        out.put("ok", true);
        out.put("authorized", true);
        out.put("authState", "authorized");
        out.put("source", "browser-session-dual-device-list");
        out.put("devices", devices);
        out.put("servers", servers);
        out.put("targetFound", foundTarget);
        return out;
    }

    private static JSONArray extractList(JSONObject response) {
        JSONObject result = response.optJSONObject("result");
        return result == null ? null : result.optJSONArray("list");
    }

    private static boolean addDevices(String server, JSONArray list, JSONArray out, Set<String> seen) throws Exception {
        boolean found = false;
        for (int i = 0; i < list.length(); i++) {
            JSONObject d = list.optJSONObject(i);
            if (d == null) continue;
            String did = d.optString("did", server + ":" + i);
            if (!seen.add(did)) continue;

            JSONObject compact = new JSONObject();
            compact.put("server", server);
            compact.put("name", d.optString("name", ""));
            compact.put("did", did);
            compact.put("model", d.optString("model", ""));
            compact.put("localip", d.optString("localip", ""));
            compact.put("mac", d.optString("mac", ""));
            compact.put("token", d.optString("token", ""));
            out.put(compact);
            if ("xiaomi.vacuum.d109gl".equals(d.optString("model", ""))) found = true;
        }
        return found;
    }

    private JSONObject rc4EncryptedCall(String server, String api, String data) throws Exception {
        String base = "https://" + ("cn".equals(server) ? "" : server + ".") + "api.io.mi.com/app";
        String url = base + "/" + api;

        LinkedHashMap<String, String> plain = new LinkedHashMap<>();
        plain.put("data", data);
        String nonce = generateTimeNonce();
        String signedNonce = signedNonce(nonce);

        LinkedHashMap<String, String> withHash = new LinkedHashMap<>(plain);
        withHash.put("rc4_hash__", generateEncSignature(url, "POST", signedNonce, plain));

        LinkedHashMap<String, String> enc = new LinkedHashMap<>();
        for (Map.Entry<String, String> e : withHash.entrySet()) {
            enc.put(e.getKey(), encryptRc4(signedNonce, e.getValue()));
        }
        enc.put("signature", generateEncSignature(url, "POST", signedNonce, enc));
        enc.put("ssecurity", ssecurity);
        enc.put("_nonce", nonce);

        Map<String, String> headers = new LinkedHashMap<>();
        headers.put("Accept-Encoding", "identity");
        headers.put("User-Agent", USER_AGENT);
        headers.put("Content-Type", "application/x-www-form-urlencoded");
        headers.put("x-xiaomi-protocal-flag-cli", "PROTOCAL-HTTP2");
        headers.put("MIOT-ENCRYPT-ALGORITHM", "ENCRYPT-RC4");
        headers.put("Cookie", cloudCookieHeader());

        HttpResult r = requestPostNoBody(url + "?" + encodeForm(enc), headers, 7000, 9000);
        if (r.code != 200) throw new IllegalStateException(server + " RC4 HTTP " + r.code);

        String raw = r.text == null ? "" : r.text.trim();
        if (raw.startsWith("{")) return new JSONObject(raw);
        String decoded = decryptRc4(signedNonce, raw);
        return new JSONObject(decoded);
    }

    private JSONObject legacyDeviceList(String server) throws Exception {
        String base = "https://" + ("cn".equals(server) ? "" : server + ".") + "api.io.mi.com/app";
        String path = "/home/device_list";
        String nonce = generateTimeNonce();
        String signedNonce = signedNonce(nonce);
        String signature = generateLegacySignature(path, signedNonce, nonce, DEVICE_LIST_DATA);

        LinkedHashMap<String, String> form = new LinkedHashMap<>();
        form.put("signature", signature);
        form.put("_nonce", nonce);
        form.put("data", DEVICE_LIST_DATA);

        Map<String, String> headers = new LinkedHashMap<>();
        headers.put("User-Agent", USER_AGENT);
        headers.put("Content-Type", "application/x-www-form-urlencoded");
        headers.put("x-xiaomi-protocal-flag-cli", "PROTOCAL-HTTP2");
        headers.put("Cookie", cloudCookieHeader());

        HttpResult r = requestPostForm(base + path, headers, form, 7000, 9000);
        if (r.code != 200) throw new IllegalStateException(server + " legacy HTTP " + r.code);
        return new JSONObject(r.text.trim());
    }

    private String cloudCookieHeader() {
        return "userId=" + userId + "; yetAnotherServiceToken=" + serviceToken +
                "; serviceToken=" + serviceToken +
                "; locale=en_GB; timezone=GMT-03:00; is_daylight=0; dst_offset=0; channel=MI_APP_STORE";
    }

    private String signedNonce(String nonce) throws Exception {
        byte[] sec = Base64.decode(ssecurity, Base64.DEFAULT);
        byte[] non = Base64.decode(nonce, Base64.DEFAULT);
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        md.update(sec);
        md.update(non);
        return Base64.encodeToString(md.digest(), Base64.NO_WRAP);
    }

    private static String generateTimeNonce() {
        byte[] all = new byte[12];
        byte[] rnd = new byte[8];
        RNG.nextBytes(rnd);
        System.arraycopy(rnd, 0, all, 0, 8);
        long minutes = System.currentTimeMillis() / 60000L;
        all[8] = (byte) ((minutes >>> 24) & 0xff);
        all[9] = (byte) ((minutes >>> 16) & 0xff);
        all[10] = (byte) ((minutes >>> 8) & 0xff);
        all[11] = (byte) (minutes & 0xff);
        return Base64.encodeToString(all, Base64.NO_WRAP);
    }

    private static String generateLegacySignature(String path, String signedNonce, String nonce, String data) throws Exception {
        String sign = path + "&" + signedNonce + "&" + nonce + "&data=" + data;
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(Base64.decode(signedNonce, Base64.DEFAULT), "HmacSHA256"));
        return Base64.encodeToString(mac.doFinal(sign.getBytes(StandardCharsets.UTF_8)), Base64.NO_WRAP);
    }

    private static String generateEncSignature(String url, String method, String signedNonce,
                                               Map<String, String> params) throws Exception {
        String marker = ".com";
        int idx = url.indexOf(marker);
        String path = idx >= 0 ? url.substring(idx + marker.length()) : new URL(url).getPath();
        path = path.replace("/app/", "/");
        StringBuilder sb = new StringBuilder();
        sb.append(method.toUpperCase(Locale.ROOT)).append('&').append(path);
        for (Map.Entry<String, String> e : params.entrySet()) {
            sb.append('&').append(e.getKey()).append('=').append(e.getValue());
        }
        sb.append('&').append(signedNonce);
        byte[] sha1 = MessageDigest.getInstance("SHA-1").digest(sb.toString().getBytes(StandardCharsets.UTF_8));
        return Base64.encodeToString(sha1, Base64.NO_WRAP);
    }

    private static String encryptRc4(String passwordB64, String payload) {
        byte[] key = Base64.decode(passwordB64, Base64.DEFAULT);
        return Base64.encodeToString(rc4(key, payload.getBytes(StandardCharsets.UTF_8), 1024), Base64.NO_WRAP);
    }

    private static String decryptRc4(String passwordB64, String payloadB64) {
        byte[] key = Base64.decode(passwordB64, Base64.DEFAULT);
        byte[] cipher = Base64.decode(payloadB64, Base64.DEFAULT);
        return new String(rc4(key, cipher, 1024), StandardCharsets.UTF_8);
    }

    private static byte[] rc4(byte[] key, byte[] input, int discard) {
        int[] s = new int[256];
        for (int x = 0; x < 256; x++) s[x] = x;
        int j = 0;
        for (int x = 0; x < 256; x++) {
            j = (j + s[x] + (key[x % key.length] & 0xff)) & 0xff;
            int t = s[x]; s[x] = s[j]; s[j] = t;
        }
        int i = 0; j = 0;
        for (int n = 0; n < discard; n++) {
            i = (i + 1) & 0xff;
            j = (j + s[i]) & 0xff;
            int t = s[i]; s[i] = s[j]; s[j] = t;
            int ignored = s[(s[i] + s[j]) & 0xff];
        }
        byte[] out = new byte[input.length];
        for (int n = 0; n < input.length; n++) {
            i = (i + 1) & 0xff;
            j = (j + s[i]) & 0xff;
            int t = s[i]; s[i] = s[j]; s[j] = t;
            int k = s[(s[i] + s[j]) & 0xff];
            out[n] = (byte) (input[n] ^ k);
        }
        return out;
    }

    private HttpResult requestGet(String url, Map<String, String> headers, int connectTimeout, int readTimeout) throws Exception {
        URL current = new URL(url);
        for (int redirect = 0; redirect < 8; redirect++) {
            HttpURLConnection c = (HttpURLConnection) current.openConnection();
            c.setRequestMethod("GET");
            c.setConnectTimeout(connectTimeout);
            c.setReadTimeout(readTimeout);
            c.setInstanceFollowRedirects(false);
            c.setRequestProperty("User-Agent", USER_AGENT);
            if (headers != null) for (Map.Entry<String, String> e : headers.entrySet()) c.setRequestProperty(e.getKey(), e.getValue());
            c.connect();
            int code = c.getResponseCode();
            String text = readAll(code >= 400 ? c.getErrorStream() : c.getInputStream());
            String location = c.getHeaderField("Location");
            c.disconnect();
            if (code >= 300 && code < 400 && location != null && !location.isEmpty()) {
                current = new URL(current, location);
                continue;
            }
            return new HttpResult(code, text);
        }
        throw new IllegalStateException("Muitos redirecionamentos Xiaomi");
    }

    private HttpResult requestPostNoBody(String url, Map<String, String> headers,
                                         int connectTimeout, int readTimeout) throws Exception {
        HttpURLConnection c = (HttpURLConnection) new URL(url).openConnection();
        c.setRequestMethod("POST");
        c.setConnectTimeout(connectTimeout);
        c.setReadTimeout(readTimeout);
        c.setInstanceFollowRedirects(false);
        c.setRequestProperty("User-Agent", USER_AGENT);
        if (headers != null) for (Map.Entry<String, String> e : headers.entrySet()) c.setRequestProperty(e.getKey(), e.getValue());
        c.connect();
        int code = c.getResponseCode();
        String text = readAll(code >= 400 ? c.getErrorStream() : c.getInputStream());
        c.disconnect();
        return new HttpResult(code, text);
    }

    private HttpResult requestPostForm(String url, Map<String, String> headers, Map<String, String> form,
                                       int connectTimeout, int readTimeout) throws Exception {
        HttpURLConnection c = (HttpURLConnection) new URL(url).openConnection();
        c.setRequestMethod("POST");
        c.setConnectTimeout(connectTimeout);
        c.setReadTimeout(readTimeout);
        c.setDoOutput(true);
        c.setInstanceFollowRedirects(false);
        c.setRequestProperty("User-Agent", USER_AGENT);
        c.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
        if (headers != null) for (Map.Entry<String, String> e : headers.entrySet()) c.setRequestProperty(e.getKey(), e.getValue());
        try (BufferedWriter w = new BufferedWriter(new OutputStreamWriter(c.getOutputStream(), StandardCharsets.UTF_8))) {
            w.write(encodeForm(form));
        }
        int code = c.getResponseCode();
        String text = readAll(code >= 400 ? c.getErrorStream() : c.getInputStream());
        c.disconnect();
        return new HttpResult(code, text);
    }

    private void importCookieHeader(String header, String domain) throws Exception {
        if (header == null) return;
        for (String part : header.split(";")) {
            String p = part.trim();
            int eq = p.indexOf('=');
            if (eq <= 0) continue;
            String name = p.substring(0, eq).trim();
            String value = p.substring(eq + 1).trim();
            if (name.isEmpty()) continue;
            HttpCookie c = new HttpCookie(name, value);
            c.setDomain(domain);
            c.setPath("/");
            c.setSecure(true);
            String host = domain.startsWith(".") ? domain.substring(1) : domain;
            cookies.getCookieStore().add(new URI("https://" + host + "/"), c);
        }
    }

    private String findCookie(String name) {
        for (HttpCookie c : cookies.getCookieStore().getCookies()) {
            if (name.equals(c.getName())) return c.getValue();
        }
        return null;
    }

    private static String readAll(InputStream in) throws Exception {
        if (in == null) return "";
        try (BufferedReader br = new BufferedReader(new InputStreamReader(new BufferedInputStream(in), StandardCharsets.UTF_8))) {
            StringBuilder sb = new StringBuilder();
            String line;
            while ((line = br.readLine()) != null) sb.append(line);
            return sb.toString();
        }
    }

    private static String encodeForm(Map<String, String> form) throws Exception {
        StringBuilder sb = new StringBuilder();
        for (Map.Entry<String, String> e : form.entrySet()) {
            if (sb.length() > 0) sb.append('&');
            sb.append(URLEncoder.encode(e.getKey(), "UTF-8"));
            sb.append('=');
            sb.append(URLEncoder.encode(e.getValue() == null ? "" : e.getValue(), "UTF-8"));
        }
        return sb.toString();
    }

    private static JSONObject parseXiaomiJson(String text) throws Exception {
        if (text == null) throw new IllegalArgumentException("Resposta Xiaomi vazia");
        return new JSONObject(text.replace("&&&START&&&", "").trim());
    }

    private static String stringOrNull(Object value) {
        if (value == null || value == JSONObject.NULL) return null;
        String s = String.valueOf(value);
        return s.isEmpty() || "null".equals(s) ? null : s;
    }

    private static String safeMessage(Throwable t) {
        String m = t.getMessage();
        return m == null ? t.getClass().getSimpleName() : m;
    }

    private static String summarizeServers(JSONArray servers) {
        StringBuilder sb = new StringBuilder("Diagnóstico: ");
        for (int i = 0; i < servers.length(); i++) {
            JSONObject s = servers.optJSONObject(i);
            if (s == null) continue;
            if (i > 0) sb.append(" | ");
            sb.append(s.optString("server", "?"));
            appendField(sb, s, "rc4Code");
            appendField(sb, s, "rc4Devices");
            appendText(sb, s, "rc4Message");
            appendText(sb, s, "rc4Error");
            appendField(sb, s, "legacyCode");
            appendField(sb, s, "legacyDevices");
            appendText(sb, s, "legacyMessage");
            appendText(sb, s, "legacyError");
        }
        return sb.toString();
    }

    private static void appendField(StringBuilder sb, JSONObject o, String key) {
        if (o.has(key)) sb.append(',').append(key).append('=').append(o.opt(key));
    }

    private static void appendText(StringBuilder sb, JSONObject o, String key) {
        String val = o.optString(key, "");
        if (val.isEmpty()) return;
        if (val.length() > 70) val = val.substring(0, 70);
        sb.append(',').append(key).append('=').append(val.replace('\n', ' '));
    }

    private static final class HttpResult {
        final int code;
        final String text;
        HttpResult(int code, String text) {
            this.code = code;
            this.text = text;
        }
    }
}
