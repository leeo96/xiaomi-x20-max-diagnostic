package com.leeo96.x20diagnostic;

import android.app.Activity;
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
    private final ExecutorService executor = Executors.newSingleThreadExecutor();

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
                    // Token is not needed for the unencrypted MiIO hello packet.
                    // Create a placeholder token only so the same client class can be used.
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
    }
}
