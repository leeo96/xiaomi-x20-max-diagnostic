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
import java.net.URI;
import java.net.URL;
import java.net.HttpURLConnection;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * Xiaomi Cloud browser-session client, revision 4.
 *
 * The important change in this revision is session isolation. We import ONLY
 * the authenticated account.xiaomi.com cookies, then exchange that account
 * session for a fresh xiaomiio STS serviceToken. We deliberately do not import
 * any pre-existing sts.api.io.mi.com/serviceToken cookie from WebView, because
 * pairing a stale serviceToken with a newly returned ssecurity makes Xiaomi's
 * RC4 request signature invalid.
 *
 * After STS completes we disable the account CookieManager and send only the
 * explicit Xiaomi Cloud API cookies, mirroring the fresh-session behavior used
 * by the public Xiaomi Cloud token extractors.
 */
public final class BrowserSessionCloudClientV4 {
    private static final String[] SERVERS = {"sg", "de", "us", "i2", "ru", "tw", "cn", "in"};
    private static final SecureRandom RNG = new SecureRandom();
    private static final String DEVICE_LIST_DATA =
            "{\"getVirtualModel\":true,\"getHuamiDevices\":1,\"get_split_device\":false,\"support_smart_home\":true}";

    private final CookieManager accountCookies = new CookieManager(null, CookiePolicy.ACCEPT_ALL);
    private final String userAgent = generateAgent();
    private String ssecurity;
    private String userId;
    private String serviceToken;

    public BrowserSessionCloudClientV4() {
        CookieHandler.setDefault(accountCookies);
    }

    public JSONObject fetchFromBrowserSession(String accountCookieHeader, String ignoredStsCookieHeader) throws Exception {
        if (accountCookieHeader == null || accountCookieHeader.trim().isEmpty()) {
            throw new IllegalStateException("Nenhuma sessão Xiaomi encontrada. Abra o login oficial primeiro.");
        }

        // Import only account cookies. Never import an existing serviceToken.
        importAccountCookieHeader(accountCookieHeader);

        Map<String, String> headers = new LinkedHashMap<>();
        headers.put("User-Agent", userAgent);
        headers.put("Content-Type", "application/x-www-form-urlencoded");
        headers.put("Cookie", sanitizedAccountCookieHeader(accountCookieHeader));

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

        // Ensure no serviceToken can survive from any earlier browser/QR attempt.
        removeCookieByName("serviceToken");
        removeCookieByName("yetAnotherServiceToken");

        Map<String, String> stsHeaders = new LinkedHashMap<>();
        stsHeaders.put("User-Agent", userAgent);
        stsHeaders.put("Content-Type", "application/x-www-form-urlencoded");
        HttpResult sts = requestGet(location, stsHeaders, 10000, 12000);
        if (sts.code >= 400) {
            throw new IllegalStateException("STS Xiaomi retornou HTTP " + sts.code + ": " + bodySnippet(sts.text));
        }

        serviceToken = findFreshServiceToken();
        if (serviceToken == null || serviceToken.isEmpty()) {
            throw new IllegalStateException("Login confirmado, mas a resposta STS não entregou um serviceToken novo");
        }

        // Match Xiaomi token-extractor behavior: use a fresh API session containing
        // only the explicitly supplied Cloud cookies below.
        CookieHandler.setDefault(null);

        return fetchDeviceLists();
    }

    private JSONObject fetchDeviceLists() throws Exception {
        JSONArray devices = new JSONArray();
        JSONArray servers = new JSONArray();
        Set<String> seen = new HashSet<>();
        boolean foundTarget = false;

        for (String server : SERVERS) {
            JSONObject st = new JSONObject();
            st.put("server", server);
            try {
                JSONObject response = rc4EncryptedCall(server, "home/device_list", DEVICE_LIST_DATA);
                int code = response.optInt("code", Integer.MIN_VALUE);
                st.put("code", code);
                st.put("message", response.optString("message", response.optString("description", "")));
                JSONObject result = response.optJSONObject("result");
                JSONArray list = result == null ? null : result.optJSONArray("list");
                st.put("devices", list == null ? 0 : list.length());
                if (code == 0 && list != null) {
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
                        devices.put(compact);
                        if ("xiaomi.vacuum.d109gl".equals(d.optString("model", ""))) foundTarget = true;
                    }
                }
            } catch (Exception ex) {
                st.put("error", safeMessage(ex));
            }
            servers.put(st);
            if (foundTarget) break;
        }

        if (devices.length() == 0) {
            JSONObject err = new JSONObject();
            err.put("ok", false);
            err.put("type", "CloudDeviceListEmptyV4");
            err.put("error", "Login xiaomiio e STS renovados, mas nenhum dispositivo veio da Cloud. " + summarizeServers(servers));
            err.put("servers", servers);
            return err;
        }

        JSONObject out = new JSONObject();
        out.put("ok", true);
        out.put("authorized", true);
        out.put("authState", "authorized");
        out.put("source", "browser-session-fresh-sts-rc4");
        out.put("devices", devices);
        out.put("servers", servers);
        out.put("targetFound", foundTarget);
        return out;
    }

    private JSONObject rc4EncryptedCall(String server, String api, String data) throws Exception {
        String base = "https://" + ("cn".equals(server) ? "" : server + ".") + "api.io.mi.com/app";
        String url = base + "/" + api;

        LinkedHashMap<String, String> params = new LinkedHashMap<>();
        params.put("data", data);
        String nonce = generateTimeNonce();
        String signedNonce = signedNonce(nonce);

        // Exact order used by current Xiaomi integrations:
        // data -> rc4_hash__ -> encrypt both -> signature -> ssecurity -> _nonce.
        params.put("rc4_hash__", sha1Sign("POST", url, params, signedNonce));
        List<String> keys = new ArrayList<>(params.keySet());
        for (String key : keys) {
            params.put(key, encryptRc4(signedNonce, params.get(key)));
        }
        params.put("signature", sha1Sign("POST", url, params, signedNonce));
        params.put("ssecurity", ssecurity);
        params.put("_nonce", nonce);

        Map<String, String> headers = new LinkedHashMap<>();
        headers.put("Accept-Encoding", "identity");
        headers.put("X-XIAOMI-PROTOCAL-FLAG-CLI", "PROTOCAL-HTTP2");
        headers.put("User-Agent", userAgent);
        headers.put("Content-Type", "application/x-www-form-urlencoded");
        headers.put("MIOT-ENCRYPT-ALGORITHM", "ENCRYPT-RC4");
        headers.put("Connection", "Keep-Alive");
        headers.put("Cookie", cloudCookieHeader());

        HttpResult r = requestPostForm(url, headers, params, 7000, 10000);
        if (r.code != 200) {
            throw new IllegalStateException(server + " RC4 HTTP " + r.code + " body=" + bodySnippet(r.text));
        }

        String raw = r.text == null ? "" : r.text.trim();
        if (raw.isEmpty()) throw new IllegalStateException(server + " RC4 resposta vazia");
        if (raw.startsWith("{")) return new JSONObject(raw);
        String decoded = decryptRc4(signedNonce, raw);
        return new JSONObject(decoded);
    }

    private String cloudCookieHeader() {
        return "userId=" + userId +
                "; yetAnotherServiceToken=" + serviceToken +
                "; serviceToken=" + serviceToken +
                "; locale=pt_BR; timezone=GMT-03:00; is_daylight=0; dst_offset=0; channel=MI_APP_STORE";
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

    private static String sha1Sign(String method, String url, Map<String, String> params, String signedNonce) throws Exception {
        String path = new URL(url).getPath();
        if (path.startsWith("/app/")) path = path.substring(4);
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
            c.setRequestProperty("User-Agent", userAgent);
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

    private HttpResult requestPostForm(String url, Map<String, String> headers, Map<String, String> form,
                                       int connectTimeout, int readTimeout) throws Exception {
        HttpURLConnection c = (HttpURLConnection) new URL(url).openConnection();
        c.setRequestMethod("POST");
        c.setConnectTimeout(connectTimeout);
        c.setReadTimeout(readTimeout);
        c.setDoOutput(true);
        c.setInstanceFollowRedirects(false);
        c.setRequestProperty("User-Agent", userAgent);
        c.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
        if (headers != null) for (Map.Entry<String, String> e : headers.entrySet()) c.setRequestProperty(e.getKey(), e.getValue());
        String body = encodeForm(form);
        try (BufferedWriter w = new BufferedWriter(new OutputStreamWriter(c.getOutputStream(), StandardCharsets.UTF_8))) {
            w.write(body);
        }
        int code = c.getResponseCode();
        String text = readAll(code >= 400 ? c.getErrorStream() : c.getInputStream());
        c.disconnect();
        return new HttpResult(code, text);
    }

    private void importAccountCookieHeader(String header) throws Exception {
        if (header == null) return;
        for (String part : header.split(";")) {
            String p = part.trim();
            int eq = p.indexOf('=');
            if (eq <= 0) continue;
            String name = p.substring(0, eq).trim();
            String value = p.substring(eq + 1).trim();
            if (name.isEmpty()) continue;
            if ("serviceToken".equalsIgnoreCase(name) || "yetAnotherServiceToken".equalsIgnoreCase(name)) continue;
            HttpCookie c = new HttpCookie(name, value);
            c.setDomain(".xiaomi.com");
            c.setPath("/");
            c.setSecure(true);
            accountCookies.getCookieStore().add(new URI("https://account.xiaomi.com/"), c);
        }
    }

    private String sanitizedAccountCookieHeader(String header) {
        if (header == null) return "";
        StringBuilder out = new StringBuilder();
        for (String part : header.split(";")) {
            String p = part.trim();
            int eq = p.indexOf('=');
            if (eq <= 0) continue;
            String name = p.substring(0, eq).trim();
            if ("serviceToken".equalsIgnoreCase(name) || "yetAnotherServiceToken".equalsIgnoreCase(name)) continue;
            if (out.length() > 0) out.append("; ");
            out.append(p);
        }
        return out.toString();
    }

    private void removeCookieByName(String name) {
        List<HttpCookie> all = new ArrayList<>(accountCookies.getCookieStore().getCookies());
        for (HttpCookie c : all) {
            if (name.equals(c.getName())) accountCookies.getCookieStore().remove(null, c);
        }
    }

    private String findFreshServiceToken() {
        String fallback = null;
        for (HttpCookie c : accountCookies.getCookieStore().getCookies()) {
            if (!"serviceToken".equals(c.getName())) continue;
            String domain = c.getDomain();
            if (domain != null && domain.contains("io.mi.com")) return c.getValue();
            fallback = c.getValue();
        }
        return fallback;
    }

    private static String generateAgent() {
        StringBuilder left = new StringBuilder();
        StringBuilder right = new StringBuilder();
        for (int i = 0; i < 18; i++) left.append((char) ('a' + RNG.nextInt(26)));
        for (int i = 0; i < 13; i++) right.append((char) ('A' + RNG.nextInt(5)));
        return left + "-" + right + " APP/com.xiaomi.mihome APPV/10.5.201";
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

    private static String bodySnippet(String text) {
        if (text == null) return "";
        String s = text.replace('\n', ' ').replace('\r', ' ').trim();
        return s.length() > 180 ? s.substring(0, 180) : s;
    }

    private static String summarizeServers(JSONArray servers) {
        StringBuilder sb = new StringBuilder("Diagnóstico: ");
        for (int i = 0; i < servers.length(); i++) {
            JSONObject s = servers.optJSONObject(i);
            if (s == null) continue;
            if (i > 0) sb.append(" | ");
            sb.append(s.optString("server", "?"));
            if (s.has("code")) sb.append(",code=").append(s.opt("code"));
            if (s.has("devices")) sb.append(",devices=").append(s.opt("devices"));
            String msg = s.optString("message", "");
            if (!msg.isEmpty()) sb.append(",message=").append(msg.length() > 70 ? msg.substring(0, 70) : msg);
            String err = s.optString("error", "");
            if (!err.isEmpty()) sb.append(",error=").append(err.length() > 150 ? err.substring(0, 150) : err);
        }
        return sb.toString();
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
