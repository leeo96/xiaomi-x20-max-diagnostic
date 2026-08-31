package com.leeo96.x20diagnostic;

import android.app.Activity;
import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import android.webkit.CookieManager;
import android.webkit.WebResourceRequest;
import android.webkit.WebSettings;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import android.widget.Toast;

/**
 * Dedicated browser surface for Xiaomi's own account pages.
 *
 * Important: no JavaScript bridge is attached to this WebView. Credentials are typed
 * directly into Xiaomi's page and are never passed to MainActivity/native code.
 */
public final class XiaomiLoginActivity extends Activity {
    private WebView webView;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        webView = new WebView(this);
        setContentView(webView);

        CookieManager cookies = CookieManager.getInstance();
        cookies.setAcceptCookie(true);
        cookies.setAcceptThirdPartyCookies(webView, true);

        WebSettings s = webView.getSettings();
        s.setJavaScriptEnabled(true);
        s.setDomStorageEnabled(true);
        s.setAllowFileAccess(false);
        s.setAllowContentAccess(false);
        s.setMixedContentMode(WebSettings.MIXED_CONTENT_NEVER_ALLOW);
        s.setSaveFormData(false);

        webView.setWebViewClient(new WebViewClient() {
            @Override
            public boolean shouldOverrideUrlLoading(WebView view, WebResourceRequest request) {
                Uri uri = request.getUrl();
                String host = uri.getHost();
                if (isAllowedXiaomiHost(host)) return false;
                startActivity(new Intent(Intent.ACTION_VIEW, uri));
                return true;
            }

            @Override
            public void onPageFinished(WebView view, String url) {
                super.onPageFinished(view, url);
                CookieManager.getInstance().flush();
                String account = CookieManager.getInstance().getCookie("https://account.xiaomi.com");
                String sts = CookieManager.getInstance().getCookie("https://sts.api.io.mi.com");
                if (containsCookie(account, "passToken") || containsCookie(sts, "serviceToken")) {
                    Toast.makeText(XiaomiLoginActivity.this,
                            "Sessão Xiaomi detectada. Volte ao X20 Max Diagnostic e toque em Buscar token.",
                            Toast.LENGTH_LONG).show();
                }
            }
        });

        webView.loadUrl("https://account.xiaomi.com/pass/serviceLogin?sid=xiaomiio&_locale=pt_BR");
    }

    private static boolean isAllowedXiaomiHost(String host) {
        if (host == null) return false;
        return host.equals("xiaomi.com") || host.endsWith(".xiaomi.com") ||
                host.equals("mi.com") || host.endsWith(".mi.com") ||
                host.equals("io.mi.com") || host.endsWith(".io.mi.com");
    }

    private static boolean containsCookie(String header, String name) {
        if (header == null) return false;
        for (String p : header.split(";")) {
            String t = p.trim();
            if (t.startsWith(name + "=")) return true;
        }
        return false;
    }

    @Override
    public void onBackPressed() {
        if (webView != null && webView.canGoBack()) {
            webView.goBack();
        } else {
            super.onBackPressed();
        }
    }

    @Override
    protected void onDestroy() {
        if (webView != null) webView.destroy();
        super.onDestroy();
    }
}
