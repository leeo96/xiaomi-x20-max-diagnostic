package com.leeo96.x20diagnostic;

import android.util.Base64;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.BufferedWriter;
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
import java.util.Locale;
import java.util.Map;
import java.util.Set;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * Browser-session Xiaomi Cloud client.
 *
 * Credentials are never passed here. This class imports only cookies from the
 * dedicated XiaomiLoginActivity, upgrades that account session to the xiaomiio
 * service session, then reads the user's device list.
 *
 * For discovery it intentionally uses the long-standing /home/device_list API
 * with HMAC-SHA256 signing. This is a second implementation path from the RC4
 * v2 home APIs used by XiaomiCloudClient and is useful both as a fallback and
 * as a diagnostic when Xiaomi returns an empty homelist.
 */
public final class BrowserSessionCloudClient {
    private static final String[] SERVERS = {"cn", "de", "us", "ru", "tw", "sg", "in", "i2"};
    private static final SecureRandom RNG = new SecureRandom();
    private static final String USER_AGENT = "Android-7.1.1-1.0.0-ONEPLUS A3010-136-X20DIAG APP/xiaomi.smarthome APPV/62830";

    private final CookieManager cookies = new CookieManager(null, CookiePolicy.ACCEPT_ALL);
    private String ssecurity;
    private String userId;
    private String serviceToken;

    public BrowserSessionCloudClient() {
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
            throw new IllegalStateException("A sessão do navegador ainda não foi convertida em sessão xiaomiio. Abra o login oficial, confirme que a conta está conectada e tente novamente.");
        }

        requestGet(location, null, 10000, 12000);
        serviceToken = findCookie("serviceToken");
        if (serviceToken == null || serviceToken.isEmpty()) {
            throw new IllegalStateException("Login confirmado, mas a Xiaomi não entregou o serviceToken xiaomiio");
        }

        return fetchLegacyDeviceLists();
    }

    private JSONObject fetchLegacyDeviceLists() throws Exception {
        JSONArray devices = new JSONArray();
        JSONArray servers = new JSONArray();
        Set<String> seen = new HashSet<>();
        boolean foundTarget = false;

        for (String server : SERVERS) {
            JSONObject status = new JSONObject();
            status.put("server", server);
            try {
                JSONObject response = legacyDeviceList(server);
                int code = response.optInt("code", Integer.MIN_VALUE);
                status.put("code", code);
                status.put("message", response.optString("message", response.optString("description", "")));

                JSONObject result = response.optJSONObject("result");
                JSONArray list = result == null ? null : result.optJSONArray("list");
                int count = list == null ? 0 : list.length();
                status.put("devices", count);
                status.put("ok", code == 0);

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
                status.put("ok", false);
                status.put("error", safeMessage(ex));
            }
            servers.put(status);
            if (foundTarget) break;
        }

        if (devices.length() == 0) {
            JSONObject err = new JSONObject();
            err.put("ok", false);
            err.put("type", "CloudDeviceListEmpty");
            err.put("error", "Login xiaomiio confirmado, mas a lista ficou vazia. Diagnóstico por servidor: " + summarizeServers(servers));
            err.put("servers", servers);
            return err;
        }

        JSONObject out = new JSONObject();
        out.put("ok", true);
        out.put("authorized", true);
        out.put("authState", "authorized");
        out.put("source", "legacy-home-device-list");
        out.put("devices", devices);
        out.put("servers", servers);
        out.put("targetFound", foundTarget);
        return out;
    }

    private JSONObject legacyDeviceList(String server) throws Exception {
        String base = "https://" + ("cn".equals(server) ? "" : server + ".") + "api.io.mi.com/app";
        String path = "/home/device_list";
        String data = "{\"getVirtualModel\":false,\"getHuamiDevices\":0}";
        String nonce = generateNonce();
        String signedNonce = signedNonce(nonce);
        String signature = generateSignature(path, signedNonce, nonce, data);

        LinkedHashMap<String, String> form = new LinkedHashMap<>();
        form.put("signature", signature);
        form.put("_nonce", nonce);
        form.put("data", data);

        Map<String, String> headers = new LinkedHashMap<>();
        headers.put("User-Agent", USER_AGENT);
        headers.put("Content-Type", "application/x-www-form-urlencoded");
        headers.put("x-xiaomi-protocal-flag-cli", "PROTOCAL-HTTP2");
        headers.put("Cookie", "userId=" + userId + "; serviceToken=" + serviceToken + "; locale=pt_BR");

        HttpResult r = requestPostForm(base + path, headers, form, 6000, 8000);
        if (r.code != 200) throw new IllegalStateException(server + " HTTP " + r.code);
        return new JSONObject(r.text.trim());
    }

    private String signedNonce(String nonce) throws Exception {
        byte[] sec = Base64.decode(ssecurity, Base64.DEFAULT);
        byte[] non = Base64.decode(nonce, Base64.DEFAULT);
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        md.update(sec);
        md.update(non);
        return Base64.encodeToString(md.digest(), Base64.NO_WRAP);
    }

    private static String generateNonce() {
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

    private static String generateSignature(String path, String signedNonce, String nonce, String data) throws Exception {
        String sign = path + "&" + signedNonce + "&" + nonce + "&data=" + data;
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(Base64.decode(signedNonce, Base64.DEFAULT), "HmacSHA256"));
        return Base64.encodeToString(mac.doFinal(sign.getBytes(StandardCharsets.UTF_8)), Base64.NO_WRAP);
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

        String body = encodeForm(form);
        try (BufferedWriter w = new BufferedWriter(new OutputStreamWriter(c.getOutputStream(), StandardCharsets.UTF_8))) {
            w.write(body);
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
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < servers.length(); i++) {
            JSONObject s = servers.optJSONObject(i);
            if (s == null) continue;
            if (sb.length() > 0) sb.append(" | ");
            sb.append(s.optString("server", "?"));
            if (s.has("code")) sb.append(":code=").append(s.optInt("code"));
            if (s.has("devices")) sb.append(",devices=").append(s.optInt("devices"));
            String msg = s.optString("message", s.optString("error", ""));
            if (!msg.isEmpty()) {
                if (msg.length() > 80) msg = msg.substring(0, 80);
                sb.append(",msg=").append(msg.replace('\n', ' '));
            }
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
