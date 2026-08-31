package com.leeo96.x20diagnostic;

import android.util.Base64;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
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
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * Minimal Xiaomi Cloud client used only to obtain the user's own MiIO device token.
 *
 * Authentication is performed with Xiaomi's QR/login-link flow. Credentials are not
 * entered into this app. The cloud session exists only in memory and is discarded
 * when the Activity/process is destroyed.
 *
 * The cloud request/signing flow follows the public Xiaomi Cloud protocol used by
 * open-source integrations such as Xiaomi Cloud Tokens Extractor.
 */
public final class XiaomiCloudClient {
    private static final String[] SERVERS = {"cn", "de", "us", "ru", "tw", "sg", "in", "i2"};
    private static final SecureRandom RNG = new SecureRandom();
    private static final String USER_AGENT = "X20Diagnostic-Android APP/com.xiaomi.mihome APPV/10.5.201";

    private final CookieManager cookies = new CookieManager(null, CookiePolicy.ACCEPT_ALL);
    private String qrImageUrl;
    private String loginUrl;
    private String longPollingUrl;
    private int qrTimeoutSeconds = 120;
    private String ssecurity;
    private String userId;
    private String serviceToken;

    public XiaomiCloudClient() {
        CookieHandler.setDefault(cookies);
    }

    public JSONObject startQrLogin() throws Exception {
        LinkedHashMap<String, String> q = new LinkedHashMap<>();
        q.put("_qrsize", "480");
        q.put("qs", "%3Fsid%3Dxiaomiio%26_json%3Dtrue");
        q.put("callback", "https://sts.api.io.mi.com/sts");
        q.put("_hasLogo", "false");
        q.put("sid", "xiaomiio");
        q.put("serviceParam", "");
        q.put("_locale", "pt_BR");
        q.put("_dc", String.valueOf(System.currentTimeMillis()));

        HttpResult r = request("GET", "https://account.xiaomi.com/longPolling/loginUrl?" + encodeQuery(q), null, 10000, 10000);
        if (r.code != 200) throw new IllegalStateException("Xiaomi login retornou HTTP " + r.code);
        JSONObject data = parseXiaomiJson(r.text);
        qrImageUrl = data.optString("qr", "");
        loginUrl = data.optString("loginUrl", "");
        longPollingUrl = data.optString("lp", "");
        qrTimeoutSeconds = data.optInt("timeout", 120);
        if (loginUrl.isEmpty() || longPollingUrl.isEmpty()) {
            throw new IllegalStateException("A Xiaomi não retornou a URL de autenticação esperada");
        }

        JSONObject out = new JSONObject();
        out.put("ok", true);
        out.put("loginUrl", loginUrl);
        out.put("qrImageUrl", qrImageUrl);
        out.put("timeout", qrTimeoutSeconds);
        return out;
    }

    public JSONObject pollQrAndFetchDevices() throws Exception {
        if (longPollingUrl == null || longPollingUrl.isEmpty()) {
            throw new IllegalStateException("Sessão de login não iniciada");
        }

        HttpResult r = request("GET", longPollingUrl, null, 12000, 15000);
        if (r.code != 200) {
            JSONObject pending = new JSONObject();
            pending.put("ok", true);
            pending.put("authorized", false);
            pending.put("http", r.code);
            pending.put("message", "Autorização ainda não concluída. Conclua o login Xiaomi e tente novamente.");
            return pending;
        }

        JSONObject data;
        try {
            data = parseXiaomiJson(r.text);
        } catch (Exception ex) {
            JSONObject pending = new JSONObject();
            pending.put("ok", true);
            pending.put("authorized", false);
            pending.put("message", "A Xiaomi ainda não confirmou o login.");
            return pending;
        }

        ssecurity = data.optString("ssecurity", "");
        userId = String.valueOf(data.opt("userId"));
        String location = data.optString("location", "");
        if (ssecurity.isEmpty() || location.isEmpty() || "null".equals(userId)) {
            JSONObject pending = new JSONObject();
            pending.put("ok", true);
            pending.put("authorized", false);
            pending.put("message", "Login ainda pendente ou expirado.");
            return pending;
        }

        // Follow Xiaomi's STS location and let CookieManager collect serviceToken.
        request("GET", location, null, 10000, 12000);
        serviceToken = findCookie("serviceToken");
        if (serviceToken == null || serviceToken.isEmpty()) {
            throw new IllegalStateException("Login confirmado, mas não foi possível obter o serviceToken Xiaomi");
        }

        JSONObject cloud = fetchDevicesAllServers();
        cloud.put("ok", true);
        cloud.put("authorized", true);
        return cloud;
    }

    private JSONObject fetchDevicesAllServers() throws Exception {
        JSONArray devices = new JSONArray();
        JSONArray serverStatus = new JSONArray();
        Set<String> seenDid = new HashSet<>();
        boolean foundTarget = false;

        for (String server : SERVERS) {
            JSONObject s = new JSONObject();
            s.put("server", server);
            try {
                List<HomeRef> homes = new ArrayList<>();
                JSONObject homesResp = encryptedCall(server, "/v2/homeroom/gethome",
                        "{\"fg\":true,\"fetch_share\":true,\"fetch_share_dev\":true,\"limit\":300,\"app_ver\":7}");
                JSONObject result = homesResp.optJSONObject("result");
                JSONArray homelist = result == null ? null : result.optJSONArray("homelist");
                if (homelist != null) {
                    for (int i = 0; i < homelist.length(); i++) {
                        JSONObject h = homelist.optJSONObject(i);
                        if (h != null) homes.add(new HomeRef(String.valueOf(h.opt("id")), userId));
                    }
                }

                // Include shared homes as the token extractor does.
                try {
                    JSONObject cnt = encryptedCall(server, "/v2/user/get_device_cnt", "{\"fetch_own\":true,\"fetch_share\":true}");
                    JSONObject cr = cnt.optJSONObject("result");
                    JSONObject share = cr == null ? null : cr.optJSONObject("share");
                    JSONArray sf = share == null ? null : share.optJSONArray("share_family");
                    if (sf != null) {
                        for (int i = 0; i < sf.length(); i++) {
                            JSONObject h = sf.optJSONObject(i);
                            if (h != null) homes.add(new HomeRef(String.valueOf(h.opt("home_id")), String.valueOf(h.opt("home_owner"))));
                        }
                    }
                } catch (Exception ignored) {}

                Set<String> seenHomes = new HashSet<>();
                int before = devices.length();
                for (HomeRef home : homes) {
                    String hk = home.id + ":" + home.owner;
                    if (!seenHomes.add(hk) || home.id == null || "null".equals(home.id)) continue;
                    String data = "{\"home_owner\":" + numericOrQuoted(home.owner) + ",\"home_id\":" + numericOrQuoted(home.id)
                            + ",\"limit\":200,\"get_split_device\":true,\"support_smart_home\":true}";
                    JSONObject dr = encryptedCall(server, "/v2/home/home_device_list", data);
                    JSONObject rr = dr.optJSONObject("result");
                    JSONArray info = rr == null ? null : rr.optJSONArray("device_info");
                    if (info == null) continue;
                    for (int i = 0; i < info.length(); i++) {
                        JSONObject d = info.optJSONObject(i);
                        if (d == null) continue;
                        String did = d.optString("did", server + ":" + i);
                        if (!seenDid.add(did)) continue;
                        JSONObject compact = new JSONObject();
                        compact.put("server", server);
                        compact.put("homeId", home.id);
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
                s.put("ok", true);
                s.put("devices", devices.length() - before);
            } catch (Exception ex) {
                s.put("ok", false);
                s.put("error", safeMessage(ex));
            }
            serverStatus.put(s);

            // Once the X20 Max is found, there is no reason to expose the user's other
            // regions/devices. This also keeps the flow quick on mobile.
            if (foundTarget) break;
        }

        JSONObject out = new JSONObject();
        out.put("devices", devices);
        out.put("servers", serverStatus);
        out.put("targetFound", foundTarget);
        return out;
    }

    private JSONObject encryptedCall(String server, String path, String data) throws Exception {
        if (ssecurity == null || serviceToken == null || userId == null) {
            throw new IllegalStateException("Sessão Xiaomi Cloud incompleta");
        }
        String base = "https://" + ("cn".equals(server) ? "" : server + ".") + "api.io.mi.com/app";
        String url = base + path;

        LinkedHashMap<String, String> plain = new LinkedHashMap<>();
        plain.put("data", data);
        long millis = System.currentTimeMillis();
        String nonce = generateNonce(millis);
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
        headers.put("Cookie", "userId=" + userId + "; yetAnotherServiceToken=" + serviceToken + "; serviceToken=" + serviceToken
                + "; locale=en_GB; timezone=GMT-03:00; is_daylight=0; dst_offset=0; channel=MI_APP_STORE");

        HttpResult r = request("POST", url + "?" + encodeQuery(enc), headers, 5500, 6500);
        if (r.code != 200) throw new IllegalStateException(server + " cloud HTTP " + r.code);
        String decoded = decryptRc4(signedNonce, r.text);
        return new JSONObject(decoded);
    }

    private String signedNonce(String nonce) throws Exception {
        byte[] a = Base64.decode(ssecurity, Base64.DEFAULT);
        byte[] b = Base64.decode(nonce, Base64.DEFAULT);
        ByteArrayOutputStream all = new ByteArrayOutputStream();
        all.write(a);
        all.write(b);
        return Base64.encodeToString(MessageDigest.getInstance("SHA-256").digest(all.toByteArray()), Base64.NO_WRAP);
    }

    private static String generateNonce(long millis) {
        byte[] n = new byte[12];
        byte[] rnd = new byte[8];
        RNG.nextBytes(rnd);
        System.arraycopy(rnd, 0, n, 0, 8);
        long minutes = millis / 60000L;
        n[8] = (byte) ((minutes >>> 24) & 0xFF);
        n[9] = (byte) ((minutes >>> 16) & 0xFF);
        n[10] = (byte) ((minutes >>> 8) & 0xFF);
        n[11] = (byte) (minutes & 0xFF);
        return Base64.encodeToString(n, Base64.NO_WRAP);
    }

    private static String generateEncSignature(String url, String method, String signedNonce, Map<String, String> params) throws Exception {
        String marker = ".com";
        int idx = url.indexOf(marker);
        String path = idx >= 0 ? url.substring(idx + marker.length()) : new URL(url).getPath();
        path = path.replace("/app/", "/");
        List<String> parts = new ArrayList<>();
        parts.add(method.toUpperCase(Locale.ROOT));
        parts.add(path);
        for (Map.Entry<String, String> e : params.entrySet()) parts.add(e.getKey() + "=" + e.getValue());
        parts.add(signedNonce);
        String joined = join(parts, "&");
        byte[] sha1 = MessageDigest.getInstance("SHA-1").digest(joined.getBytes(StandardCharsets.UTF_8));
        return Base64.encodeToString(sha1, Base64.NO_WRAP);
    }

    @SuppressWarnings("unused")
    private static String generateSignature(String url, String signedNonce, String nonce, Map<String, String> params) throws Exception {
        int idx = url.indexOf(".com");
        String path = idx >= 0 ? url.substring(idx + 4) : new URL(url).getPath();
        List<String> parts = new ArrayList<>();
        parts.add(path);
        parts.add(signedNonce);
        parts.add(nonce);
        for (Map.Entry<String, String> e : params.entrySet()) parts.add(e.getKey() + "=" + e.getValue());
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(Base64.decode(signedNonce, Base64.DEFAULT), "HmacSHA256"));
        return Base64.encodeToString(mac.doFinal(join(parts, "&").getBytes(StandardCharsets.UTF_8)), Base64.NO_WRAP);
    }

    private static String encryptRc4(String passwordB64, String payload) {
        byte[] key = Base64.decode(passwordB64, Base64.DEFAULT);
        byte[] out = rc4(key, payload.getBytes(StandardCharsets.UTF_8), 1024);
        return Base64.encodeToString(out, Base64.NO_WRAP);
    }

    private static String decryptRc4(String passwordB64, String payloadB64) {
        byte[] key = Base64.decode(passwordB64, Base64.DEFAULT);
        byte[] cipher = Base64.decode(payloadB64, Base64.DEFAULT);
        return new String(rc4(key, cipher, 1024), StandardCharsets.UTF_8);
    }

    private static byte[] rc4(byte[] key, byte[] input, int discard) {
        int[] s = new int[256];
        for (int i = 0; i < 256; i++) s[i] = i;
        int j = 0;
        for (int i = 0; i < 256; i++) {
            j = (j + s[i] + (key[i % key.length] & 0xFF)) & 0xFF;
            int t = s[i]; s[i] = s[j]; s[j] = t;
        }
        int i = 0; j = 0;
        for (int n = 0; n < discard; n++) {
            i = (i + 1) & 0xFF;
            j = (j + s[i]) & 0xFF;
            int t = s[i]; s[i] = s[j]; s[j] = t;
            s[(s[i] + s[j]) & 0xFF] ^= 0; // advance PRGA without storing byte
        }
        byte[] out = new byte[input.length];
        for (int n = 0; n < input.length; n++) {
            i = (i + 1) & 0xFF;
            j = (j + s[i]) & 0xFF;
            int t = s[i]; s[i] = s[j]; s[j] = t;
            int k = s[(s[i] + s[j]) & 0xFF];
            out[n] = (byte) (input[n] ^ k);
        }
        return out;
    }

    private HttpResult request(String method, String url, Map<String, String> headers, int connectTimeout, int readTimeout) throws Exception {
        URL current = new URL(url);
        for (int redirect = 0; redirect < 8; redirect++) {
            HttpURLConnection c = (HttpURLConnection) current.openConnection();
            c.setRequestMethod(method);
            c.setConnectTimeout(connectTimeout);
            c.setReadTimeout(readTimeout);
            c.setInstanceFollowRedirects(false);
            c.setRequestProperty("User-Agent", USER_AGENT);
            if (headers != null) for (Map.Entry<String, String> e : headers.entrySet()) c.setRequestProperty(e.getKey(), e.getValue());
            c.connect();
            int code = c.getResponseCode();
            InputStream raw = code >= 400 ? c.getErrorStream() : c.getInputStream();
            String text = readAll(raw);
            String location = c.getHeaderField("Location");
            c.disconnect();
            if (code >= 300 && code < 400 && location != null && !location.isEmpty()) {
                current = new URL(current, location);
                method = "GET";
                continue;
            }
            return new HttpResult(code, text, current.toString());
        }
        throw new IllegalStateException("Muitos redirecionamentos Xiaomi");
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

    private static JSONObject parseXiaomiJson(String text) throws Exception {
        if (text == null) throw new IllegalArgumentException("Resposta Xiaomi vazia");
        String clean = text.replace("&&&START&&&", "").trim();
        return new JSONObject(clean);
    }

    private static String encodeQuery(Map<String, String> params) throws Exception {
        List<String> out = new ArrayList<>();
        for (Map.Entry<String, String> e : params.entrySet()) {
            out.add(URLEncoder.encode(e.getKey(), "UTF-8") + "=" + URLEncoder.encode(e.getValue() == null ? "" : e.getValue(), "UTF-8"));
        }
        return join(out, "&");
    }

    private static String join(List<String> parts, String sep) {
        StringBuilder sb = new StringBuilder();
        for (String p : parts) {
            if (sb.length() > 0) sb.append(sep);
            sb.append(p);
        }
        return sb.toString();
    }

    private static String numericOrQuoted(String value) {
        if (value != null && value.matches("-?[0-9]+")) return value;
        return JSONObject.quote(value == null ? "" : value);
    }

    private static String safeMessage(Throwable t) {
        String m = t.getMessage();
        return m == null ? t.getClass().getSimpleName() : m;
    }

    private static final class HomeRef {
        final String id;
        final String owner;
        HomeRef(String id, String owner) { this.id = id; this.owner = owner; }
    }

    private static final class HttpResult {
        final int code;
        final String text;
        final String url;
        HttpResult(int code, String text, String url) { this.code = code; this.text = text; this.url = url; }
    }
}
