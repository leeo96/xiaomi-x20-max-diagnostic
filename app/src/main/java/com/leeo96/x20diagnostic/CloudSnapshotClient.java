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
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/** Read-only Xiaomi Cloud MIoT property reader for xiaomi.vacuum.d109gl. */
public final class CloudSnapshotClient {
    private static final String[] SERVERS = {"sg", "de", "us", "i2", "ru", "tw", "cn", "in"};
    private static final SecureRandom RNG = new SecureRandom();
    private static final String DEVICE_LIST_DATA =
            "{\"getVirtualModel\":true,\"getHuamiDevices\":1,\"get_split_device\":false,\"support_smart_home\":true}";

    private final CookieManager accountCookies = new CookieManager(null, CookiePolicy.ACCEPT_ALL);
    private final String userAgent = "X20Diagnostic-Cloud-" + Long.toHexString(System.nanoTime()) + " APP/com.xiaomi.mihome APPV/10.5.201";
    private String ssecurity;
    private String userId;
    private String serviceToken;

    public JSONObject fetchProperties(String accountCookieHeader, List<MiioClient.Property> properties) throws Exception {
        if (accountCookieHeader == null || accountCookieHeader.trim().isEmpty()) {
            throw new IllegalStateException("Sessão Xiaomi ausente. Faça o login oficial novamente.");
        }
        if (properties == null || properties.isEmpty()) throw new IllegalArgumentException("Nenhuma propriedade solicitada");

        CookieHandler.setDefault(accountCookies);
        importAccountCookieHeader(accountCookieHeader);

        Map<String, String> loginHeaders = new LinkedHashMap<>();
        loginHeaders.put("User-Agent", userAgent);
        loginHeaders.put("Content-Type", "application/x-www-form-urlencoded");
        loginHeaders.put("Cookie", sanitizedAccountCookieHeader(accountCookieHeader));

        HttpResult login = requestGet(
                "https://account.xiaomi.com/pass/serviceLogin?sid=xiaomiio&_json=true",
                loginHeaders, 10000, 10000);
        if (login.code != 200) throw new IllegalStateException("Conta Xiaomi HTTP " + login.code);

        JSONObject auth = parseXiaomiJson(login.text);
        ssecurity = auth.optString("ssecurity", "");
        userId = stringOrNull(auth.opt("userId"));
        String location = auth.optString("location", "");
        if (ssecurity.isEmpty() || userId == null || location.isEmpty()) {
            throw new IllegalStateException("A sessão Xiaomi não foi convertida em sessão xiaomiio");
        }

        removeCookieByName("serviceToken");
        removeCookieByName("yetAnotherServiceToken");
        HttpResult sts = requestGet(location, null, 10000, 12000);
        if (sts.code >= 400) throw new IllegalStateException("STS Xiaomi HTTP " + sts.code + " " + snippet(sts.text));
        serviceToken = findCookie("serviceToken");
        if (serviceToken == null || serviceToken.isEmpty()) throw new IllegalStateException("STS não entregou serviceToken");

        CookieHandler.setDefault(null);
        Target target = findTarget();
        if (target == null) throw new IllegalStateException("X20 Max não encontrado na Xiaomi Cloud");

        JSONArray params = new JSONArray();
        for (MiioClient.Property p : properties) {
            JSONObject item = new JSONObject();
            item.put("did", target.did);
            item.put("siid", p.siid);
            item.put("piid", p.piid);
            params.put(item);
        }
        JSONObject data = new JSONObject();
        data.put("params", params);
        JSONObject response = rc4Call(target.server, "miotspec/prop/get", data.toString());
        int code = response.optInt("code", Integer.MIN_VALUE);
        if (code != 0) throw new IllegalStateException("Cloud prop/get code=" + code + " msg=" + response.optString("message", ""));

        JSONArray result = response.optJSONArray("result");
        if (result == null) result = new JSONArray();
        JSONArray enriched = new JSONArray();
        for (int i = 0; i < result.length(); i++) {
            JSONObject r = result.optJSONObject(i);
            if (r == null) continue;
            JSONObject e = new JSONObject(r.toString());
            int siid = e.optInt("siid", -1);
            int piid = e.optInt("piid", -1);
            for (MiioClient.Property p : properties) {
                if (p.siid == siid && p.piid == piid) { e.put("name", p.name); break; }
            }
            enriched.put(e);
        }

        JSONObject out = new JSONObject();
        out.put("ok", true);
        out.put("source", "xiaomi-cloud-miotspec-prop-get");
        out.put("server", target.server);
        out.put("did", target.did);
        out.put("results", enriched);
        return out;
    }

    private Target findTarget() throws Exception {
        for (String server : SERVERS) {
            try {
                JSONObject response = rc4Call(server, "home/device_list", DEVICE_LIST_DATA);
                if (response.optInt("code", Integer.MIN_VALUE) != 0) continue;
                JSONObject res = response.optJSONObject("result");
                JSONArray list = res == null ? null : res.optJSONArray("list");
                if (list == null) continue;
                for (int i = 0; i < list.length(); i++) {
                    JSONObject d = list.optJSONObject(i);
                    if (d != null && "xiaomi.vacuum.d109gl".equals(d.optString("model", ""))) {
                        return new Target(server, d.optString("did", ""));
                    }
                }
            } catch (Exception ignored) {}
        }
        return null;
    }

    private JSONObject rc4Call(String server, String api, String data) throws Exception {
        String base = "https://" + ("cn".equals(server) ? "" : server + ".") + "api.io.mi.com/app";
        String url = base + "/" + api;
        LinkedHashMap<String, String> params = new LinkedHashMap<>();
        params.put("data", data);
        String nonce = generateNonce();
        String signedNonce = signedNonce(nonce);
        params.put("rc4_hash__", sha1Sign("POST", url, params, signedNonce));
        List<String> keys = new ArrayList<>(params.keySet());
        for (String k : keys) params.put(k, encryptRc4(signedNonce, params.get(k)));
        params.put("signature", sha1Sign("POST", url, params, signedNonce));
        params.put("ssecurity", ssecurity);
        params.put("_nonce", nonce);

        Map<String, String> headers = new LinkedHashMap<>();
        headers.put("Accept-Encoding", "identity");
        headers.put("X-XIAOMI-PROTOCAL-FLAG-CLI", "PROTOCAL-HTTP2");
        headers.put("User-Agent", userAgent);
        headers.put("Content-Type", "application/x-www-form-urlencoded");
        headers.put("MIOT-ENCRYPT-ALGORITHM", "ENCRYPT-RC4");
        headers.put("Cookie", cloudCookieHeader());

        HttpResult r = requestPostForm(url, headers, params, 7000, 12000);
        if (r.code != 200) throw new IllegalStateException(server + " HTTP " + r.code + " body=" + snippet(r.text));
        String raw = r.text == null ? "" : r.text.trim();
        if (raw.startsWith("{")) return new JSONObject(raw);
        return new JSONObject(decryptRc4(signedNonce, raw));
    }

    private String cloudCookieHeader() {
        return "userId=" + userId + "; yetAnotherServiceToken=" + serviceToken + "; serviceToken=" + serviceToken +
                "; locale=pt_BR; timezone=GMT-03:00; is_daylight=0; dst_offset=0; channel=MI_APP_STORE";
    }

    private String signedNonce(String nonce) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        md.update(Base64.decode(ssecurity, Base64.DEFAULT));
        md.update(Base64.decode(nonce, Base64.DEFAULT));
        return Base64.encodeToString(md.digest(), Base64.NO_WRAP);
    }

    private static String generateNonce() {
        byte[] all = new byte[12];
        byte[] rnd = new byte[8]; RNG.nextBytes(rnd); System.arraycopy(rnd, 0, all, 0, 8);
        long m = System.currentTimeMillis() / 60000L;
        all[8]=(byte)(m>>>24); all[9]=(byte)(m>>>16); all[10]=(byte)(m>>>8); all[11]=(byte)m;
        return Base64.encodeToString(all, Base64.NO_WRAP);
    }

    private static String sha1Sign(String method, String url, Map<String,String> params, String signedNonce) throws Exception {
        String path = new URL(url).getPath();
        if (path.startsWith("/app/")) path = path.substring(4);
        StringBuilder sb = new StringBuilder(method.toUpperCase(Locale.ROOT)).append('&').append(path);
        for (Map.Entry<String,String> e : params.entrySet()) sb.append('&').append(e.getKey()).append('=').append(e.getValue());
        sb.append('&').append(signedNonce);
        return Base64.encodeToString(MessageDigest.getInstance("SHA-1").digest(sb.toString().getBytes(StandardCharsets.UTF_8)), Base64.NO_WRAP);
    }

    private static String encryptRc4(String keyB64, String text) {
        return Base64.encodeToString(rc4(Base64.decode(keyB64, Base64.DEFAULT), text.getBytes(StandardCharsets.UTF_8), 1024), Base64.NO_WRAP);
    }
    private static String decryptRc4(String keyB64, String textB64) {
        return new String(rc4(Base64.decode(keyB64, Base64.DEFAULT), Base64.decode(textB64, Base64.DEFAULT), 1024), StandardCharsets.UTF_8);
    }
    private static byte[] rc4(byte[] key, byte[] input, int discard) {
        int[] s=new int[256]; for(int x=0;x<256;x++)s[x]=x; int j=0;
        for(int x=0;x<256;x++){j=(j+s[x]+(key[x%key.length]&255))&255;int t=s[x];s[x]=s[j];s[j]=t;}
        int i=0;j=0; for(int n=0;n<discard;n++){i=(i+1)&255;j=(j+s[i])&255;int t=s[i];s[i]=s[j];s[j]=t;int z=s[(s[i]+s[j])&255];}
        byte[] out=new byte[input.length];
        for(int n=0;n<input.length;n++){i=(i+1)&255;j=(j+s[i])&255;int t=s[i];s[i]=s[j];s[j]=t;out[n]=(byte)(input[n]^s[(s[i]+s[j])&255]);}
        return out;
    }

    private HttpResult requestGet(String url, Map<String,String> headers, int ct, int rt) throws Exception {
        URL current=new URL(url);
        for(int red=0;red<8;red++){
            HttpURLConnection c=(HttpURLConnection)current.openConnection(); c.setRequestMethod("GET"); c.setConnectTimeout(ct); c.setReadTimeout(rt); c.setInstanceFollowRedirects(false); c.setRequestProperty("User-Agent",userAgent);
            if(headers!=null)for(Map.Entry<String,String>e:headers.entrySet())c.setRequestProperty(e.getKey(),e.getValue());
            int code=c.getResponseCode(); String text=readAll(code>=400?c.getErrorStream():c.getInputStream()); String loc=c.getHeaderField("Location"); c.disconnect();
            if(code>=300&&code<400&&loc!=null&&!loc.isEmpty()){current=new URL(current,loc);continue;} return new HttpResult(code,text);
        }
        throw new IllegalStateException("Muitos redirecionamentos Xiaomi");
    }
    private HttpResult requestPostForm(String url, Map<String,String> headers, Map<String,String> form, int ct, int rt) throws Exception {
        HttpURLConnection c=(HttpURLConnection)new URL(url).openConnection(); c.setRequestMethod("POST"); c.setConnectTimeout(ct); c.setReadTimeout(rt); c.setDoOutput(true); c.setInstanceFollowRedirects(false); c.setRequestProperty("User-Agent",userAgent); c.setRequestProperty("Content-Type","application/x-www-form-urlencoded");
        if(headers!=null)for(Map.Entry<String,String>e:headers.entrySet())c.setRequestProperty(e.getKey(),e.getValue());
        try(BufferedWriter w=new BufferedWriter(new OutputStreamWriter(c.getOutputStream(),StandardCharsets.UTF_8))){w.write(encodeForm(form));}
        int code=c.getResponseCode(); String text=readAll(code>=400?c.getErrorStream():c.getInputStream()); c.disconnect(); return new HttpResult(code,text);
    }

    private void importAccountCookieHeader(String header) throws Exception {
        for(String part:header.split(";")){String p=part.trim();int eq=p.indexOf('=');if(eq<=0)continue;String n=p.substring(0,eq).trim();if("serviceToken".equals(n)||"yetAnotherServiceToken".equals(n))continue;HttpCookie c=new HttpCookie(n,p.substring(eq+1).trim());c.setDomain(".xiaomi.com");c.setPath("/");c.setSecure(true);accountCookies.getCookieStore().add(new URI("https://account.xiaomi.com/"),c);}
    }
    private String sanitizedAccountCookieHeader(String header){StringBuilder sb=new StringBuilder();for(String part:header.split(";")){String p=part.trim();int eq=p.indexOf('=');if(eq<=0)continue;String n=p.substring(0,eq).trim();if("serviceToken".equals(n)||"yetAnotherServiceToken".equals(n))continue;if(sb.length()>0)sb.append("; ");sb.append(p);}return sb.toString();}
    private void removeCookieByName(String name){List<HttpCookie> copy=new ArrayList<>(accountCookies.getCookieStore().getCookies());for(HttpCookie c:copy)if(name.equals(c.getName()))accountCookies.getCookieStore().remove(null,c);}
    private String findCookie(String name){for(HttpCookie c:accountCookies.getCookieStore().getCookies())if(name.equals(c.getName()))return c.getValue();return null;}
    private static JSONObject parseXiaomiJson(String t)throws Exception{return new JSONObject((t==null?"":t).replace("&&&START&&&","").trim());}
    private static String stringOrNull(Object v){if(v==null||v==JSONObject.NULL)return null;String s=String.valueOf(v);return s.isEmpty()||"null".equals(s)?null:s;}
    private static String readAll(InputStream in)throws Exception{if(in==null)return"";try(BufferedReader br=new BufferedReader(new InputStreamReader(new BufferedInputStream(in),StandardCharsets.UTF_8))){StringBuilder sb=new StringBuilder();String l;while((l=br.readLine())!=null)sb.append(l);return sb.toString();}}
    private static String encodeForm(Map<String,String> f)throws Exception{StringBuilder sb=new StringBuilder();for(Map.Entry<String,String>e:f.entrySet()){if(sb.length()>0)sb.append('&');sb.append(URLEncoder.encode(e.getKey(),"UTF-8")).append('=').append(URLEncoder.encode(e.getValue()==null?"":e.getValue(),"UTF-8"));}return sb.toString();}
    private static String snippet(String s){if(s==null)return"";s=s.replace('\n',' ').replace('\r',' ');return s.length()>180?s.substring(0,180):s;}

    private static final class Target { final String server,did; Target(String s,String d){server=s;did=d;} }
    private static final class HttpResult { final int code; final String text; HttpResult(int c,String t){code=c;text=t;} }
}
