package com.leeo96.x20diagnostic;

import android.app.Activity;
import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import android.webkit.JavascriptInterface;
import android.webkit.WebSettings;
import android.webkit.WebView;

import org.json.JSONObject;

import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class MainActivity extends Activity {
    private WebView webView;
    private final ExecutorService executor = Executors.newFixedThreadPool(2);
    private volatile XiaomiCloudClient cloudClient;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        webView = new WebView(this);
        setContentView(webView);

        WebSettings settings = webView.getSettings();
        settings.setJavaScriptEnabled(true);
        settings.setDomStorageEnabled(true);
        settings.setAllowFileAccess(false);
        settings.setAllowContentAccess(false);
        settings.setMixedContentMode(WebSettings.MIXED_CONTENT_NEVER_ALLOW);

        webView.addJavascriptInterface(new MiioBridge(), "AndroidMiio");
        webView.loadUrl("file:///android_asset/index.html");
    }

    @Override
    protected void onDestroy() {
        executor.shutdownNow();
        cloudClient = null;
        if (webView != null) webView.destroy();
        super.onDestroy();
    }

    private void deliver(String requestId, JSONObject payload) {
        final String js = "window.onNativeResult(" + JSONObject.quote(requestId) + "," + JSONObject.quote(payload.toString()) + ");";
        runOnUiThread(() -> webView.evaluateJavascript(js, null));
    }

    private JSONObject errorPayload(Throwable t) {
        JSONObject out = new JSONObject();
        try {
            out.put("ok", false);
            String msg = t.getMessage();
            if (msg == null || msg.trim().isEmpty()) msg = t.getClass().getSimpleName();
            out.put("error", msg);
            out.put("type", t.getClass().getSimpleName());
        } catch (Exception ignored) {
        }
        return out;
    }

    public final class MiioBridge {
        @JavascriptInterface
        public void hello(String requestId, String ip) {
            executor.execute(() -> {
                try {
                    MiioClient client = new MiioClient("00000000000000000000000000000000");
                    deliver(requestId, client.helloOnly(ip));
                } catch (Throwable t) {
                    deliver(requestId, errorPayload(t));
                }
            });
        }

        @JavascriptInterface
        public void query(String requestId, String ip, String token, String propertiesJson) {
            executor.execute(() -> {
                try {
                    List<MiioClient.Property> properties = MiioClient.parsePropertyList(propertiesJson);
                    MiioClient client = new MiioClient(token);
                    deliver(requestId, client.readProperties(ip, properties));
                } catch (Throwable t) {
                    deliver(requestId, errorPayload(t));
                }
            });
        }

        @JavascriptInterface
        public void scanIps(String requestId) {
            executor.execute(() -> {
                try {
                    deliver(requestId, NetworkScanner.scan(MainActivity.this));
                } catch (Throwable t) {
                    deliver(requestId, errorPayload(t));
                }
            });
        }

        @JavascriptInterface
        public void cloudStart(String requestId) {
            executor.execute(() -> {
                try {
                    XiaomiCloudClient client = new XiaomiCloudClient();
                    JSONObject result = client.startQrLogin();
                    cloudClient = client;
                    deliver(requestId, result);
                } catch (Throwable t) {
                    cloudClient = null;
                    deliver(requestId, errorPayload(t));
                }
            });
        }

        @JavascriptInterface
        public void cloudPoll(String requestId) {
            executor.execute(() -> {
                try {
                    XiaomiCloudClient client = cloudClient;
                    if (client == null) throw new IllegalStateException("Inicie primeiro o login Xiaomi Cloud");
                    deliver(requestId, client.pollQrAndFetchDevices());
                } catch (Throwable t) {
                    deliver(requestId, errorPayload(t));
                }
            });
        }

        @JavascriptInterface
        public void openExternal(String url) {
            runOnUiThread(() -> {
                try {
                    Uri uri = Uri.parse(url);
                    String host = uri.getHost();
                    if (!"https".equalsIgnoreCase(uri.getScheme()) || host == null || !host.endsWith("xiaomi.com")) {
                        throw new IllegalArgumentException("URL de login não pertence à Xiaomi");
                    }
                    startActivity(new Intent(Intent.ACTION_VIEW, uri));
                } catch (Throwable t) {
                    JSONObject out = errorPayload(t);
                    final String js = "window.onExternalOpenError(" + JSONObject.quote(out.optString("error", "Erro ao abrir login")) + ");";
                    webView.evaluateJavascript(js, null);
                }
            });
        }
    }
}
