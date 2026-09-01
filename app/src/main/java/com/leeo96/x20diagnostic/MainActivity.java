package com.leeo96.x20diagnostic;

import android.app.Activity;
import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import android.webkit.JavascriptInterface;
import android.webkit.WebSettings;
import android.webkit.WebView;
import android.webkit.WebViewClient;

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
        settings.setSaveFormData(false);

        webView.addJavascriptInterface(new MiioBridge(), "AndroidMiio");
        webView.setWebViewClient(new WebViewClient() {
            @Override
            public void onPageFinished(WebView view, String url) {
                injectCloudSnapshotUi();
            }
        });
        webView.loadUrl("file:///android_asset/index.html");
    }

    private void injectCloudSnapshotUi() {
        String js = "(function(){" +
                "if(window.__cloudSnapInstalled)return;window.__cloudSnapInstalled=true;" +
                "var sub=document.querySelector('.sub');if(sub)sub.innerHTML=sub.innerHTML+' · <b>v0.3.5 cloud</b>';" +
                "var P=[" +
                "{siid:2,piid:2,name:'status'}," +
                "{siid:2,piid:3,name:'fault'}," +
                "{siid:2,piid:11,name:'mop-status'}," +
                "{siid:2,piid:18,name:'base-station-working-status'}," +
                "{siid:2,piid:30,name:'water-output-for-washing-mop'}," +
                "{siid:2,piid:34,name:'auto-mop-dry'}," +
                "{siid:2,piid:35,name:'auto-water-change'}," +
                "{siid:2,piid:36,name:'use-detergent'}," +
                "{siid:2,piid:40,name:'current-cleaning-config'}," +
                "{siid:2,piid:53,name:'water-check-list'}," +
                "{siid:2,piid:54,name:'water-check-status'}," +
                "{siid:2,piid:59,name:'detergent-self-delivery'}," +
                "{siid:2,piid:60,name:'mop-water-output-level-no-tank'}," +
                "{siid:2,piid:61,name:'frequency-mop-wash-no-tank'}," +
                "{siid:2,piid:62,name:'auto-water-change-installed'}," +
                "{siid:2,piid:66,name:'fault-ids'}," +
                "{siid:2,piid:67,name:'action-result'}," +
                "{siid:2,piid:70,name:'plugin-info-remind'}," +
                "{siid:2,piid:71,name:'detergent-depletion-reminder'}," +
                "{siid:2,piid:72,name:'notice'}," +
                "{siid:2,piid:82,name:'auto-dust-arrest-power-level'}," +
                "{siid:2,piid:84,name:'wash-mop-water-temperature'}," +
                "{siid:18,piid:1,name:'detergent-left-level'}," +
                "{siid:20,piid:7,name:'sewage-self-cleaning'}," +
                "{siid:20,piid:8,name:'self-cleaning-time'}];" +
                "window.__cloudProps=P;window.__cloudSnapA=null;" +
                "function vm(v){if(v===null)return'null';if(typeof v==='object')return JSON.stringify(v);return String(v)}" +
                "function mp(rs){var m={};(rs||[]).forEach(function(r){if(r.code===0||r.code===undefined)m[r.siid+'/'+r.piid]={v:vm(r.value),name:r.name||''};});return m}" +
                "function summary(d){var m=mp(d.results),ks=['2/2','2/3','2/18','2/53','2/54','2/66','2/67','2/70','2/72','20/7','20/8'];return ks.filter(k=>m[k]).map(k=>k+' '+m[k].name+' = '+m[k].v).join('\\n')}" +
                "window.cloudReadNow=async function(){var o=document.getElementById('cloudSnapOut');o.textContent='Lendo propriedades diretamente pela Xiaomi Cloud…';try{var d=await rawNative(function(id){AndroidMiio.cloudQuery(id,JSON.stringify(P))});o.textContent='Cloud '+d.server+' · DID '+d.did+'\\n\\n'+summary(d);o.className='status ok'}catch(e){o.textContent='Falha na leitura Cloud: '+e.message;o.className='status err'}};" +
                "window.cloudSnapA=async function(){var o=document.getElementById('cloudSnapOut');o.textContent='Capturando Snapshot Cloud A…';try{var d=await rawNative(function(id){AndroidMiio.cloudQuery(id,JSON.stringify(P))});window.__cloudSnapA=mp(d.results);o.textContent='Snapshot Cloud A salvo ('+Object.keys(window.__cloudSnapA).length+' propriedades). Agora provoque a operação/erro e faça B.';o.className='status ok'}catch(e){o.textContent='Falha no Snapshot A: '+e.message;o.className='status err'}};" +
                "window.cloudSnapB=async function(){var o=document.getElementById('cloudSnapOut');if(!window.__cloudSnapA){o.textContent='Faça primeiro o Snapshot Cloud A.';o.className='status err';return}o.textContent='Capturando Snapshot Cloud B…';try{var d=await rawNative(function(id){AndroidMiio.cloudQuery(id,JSON.stringify(P))});var b=mp(d.results),a=window.__cloudSnapA,keys=Array.from(new Set(Object.keys(a).concat(Object.keys(b)))).sort(),chg=[];keys.forEach(function(k){var av=a[k]?a[k].v:'<sem resposta>',bv=b[k]?b[k].v:'<sem resposta>';if(av!==bv)chg.push(k+' '+((b[k]&&b[k].name)||(a[k]&&a[k].name)||'')+' : '+av+'  →  '+bv)});o.textContent=chg.length?('Mudanças Cloud detectadas ('+chg.length+'):\\n\\n'+chg.join('\\n')):'Nenhuma das propriedades Cloud monitoradas mudou entre A e B.';o.className=chg.length?'status ok':'status'}catch(e){o.textContent='Falha no Snapshot B: '+e.message;o.className='status err'}};" +
                "var cards=document.querySelectorAll('.card'),anchor=null;for(var i=0;i<cards.length;i++){if(cards[i].textContent.indexOf('Comparar sensores/estados')>=0){anchor=cards[i];break}}" +
                "var c=document.createElement('div');c.className='card';c.innerHTML='<b>Diagnóstico pela Xiaomi Cloud</b><p class=\"tiny\">O X20 Max pode devolver valores locais em cache. Estes botões consultam <code>miotspec/prop/get</code> diretamente na Cloud usando a sessão Xiaomi autenticada.</p><div class=\"actions\"><button class=\"goodbtn\" onclick=\"cloudReadNow()\">Ler Cloud agora</button><button class=\"secondary\" onclick=\"cloudSnapA()\">Snapshot Cloud A</button><button class=\"secondary\" onclick=\"cloudSnapB()\">Snapshot Cloud B + comparar</button></div><div id=\"cloudSnapOut\" class=\"status\">Faça o login Xiaomi uma vez; depois use estes snapshots em vez dos snapshots locais.</div>';" +
                "if(anchor&&anchor.parentNode)anchor.parentNode.insertBefore(c,anchor);else document.querySelector('.wrap').appendChild(c);" +
                "})();";
        webView.evaluateJavascript(js, null);
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
        } catch (Exception ignored) {}
        return out;
    }

    public final class MiioBridge {
        @JavascriptInterface
        public void hello(String requestId, String ip) {
            executor.execute(() -> {
                try {
                    MiioClient client = new MiioClient("00000000000000000000000000000000");
                    deliver(requestId, client.helloOnly(ip));
                } catch (Throwable t) { deliver(requestId, errorPayload(t)); }
            });
        }

        @JavascriptInterface
        public void query(String requestId, String ip, String token, String propertiesJson) {
            executor.execute(() -> {
                try {
                    List<MiioClient.Property> properties = MiioClient.parsePropertyList(propertiesJson);
                    MiioClient client = new MiioClient(token);
                    deliver(requestId, client.readProperties(ip, properties));
                } catch (Throwable t) { deliver(requestId, errorPayload(t)); }
            });
        }

        @JavascriptInterface
        public void cloudQuery(String requestId, String propertiesJson) {
            executor.execute(() -> {
                try {
                    List<MiioClient.Property> properties = MiioClient.parsePropertyList(propertiesJson);
                    android.webkit.CookieManager wc = android.webkit.CookieManager.getInstance();
                    String accountCookies = wc.getCookie("https://account.xiaomi.com");
                    CloudSnapshotClient client = new CloudSnapshotClient();
                    deliver(requestId, client.fetchProperties(accountCookies, properties));
                } catch (Throwable t) { deliver(requestId, errorPayload(t)); }
            });
        }

        @JavascriptInterface
        public void scanIps(String requestId) {
            executor.execute(() -> {
                try { deliver(requestId, NetworkScanner.scan(MainActivity.this)); }
                catch (Throwable t) { deliver(requestId, errorPayload(t)); }
            });
        }

        @JavascriptInterface
        public void openOfficialLogin() {
            runOnUiThread(() -> startActivity(new Intent(MainActivity.this, XiaomiLoginActivity.class)));
        }

        @JavascriptInterface
        public void cloudFromBrowserSession(String requestId) {
            executor.execute(() -> {
                try {
                    android.webkit.CookieManager wc = android.webkit.CookieManager.getInstance();
                    String accountCookies = wc.getCookie("https://account.xiaomi.com");
                    String stsCookies = wc.getCookie("https://sts.api.io.mi.com");
                    BrowserSessionCloudClientV4 client = new BrowserSessionCloudClientV4();
                    deliver(requestId, client.fetchFromBrowserSession(accountCookies, stsCookies));
                } catch (Throwable t) { deliver(requestId, errorPayload(t)); }
            });
        }

        @JavascriptInterface
        public void clearOfficialLoginSession(String requestId) {
            runOnUiThread(() -> {
                try {
                    android.webkit.CookieManager cm = android.webkit.CookieManager.getInstance();
                    cm.removeAllCookies(value -> {
                        cm.flush();
                        JSONObject out = new JSONObject();
                        try { out.put("ok", true); out.put("cleared", true); } catch (Exception ignored) {}
                        deliver(requestId, out);
                    });
                } catch (Throwable t) { deliver(requestId, errorPayload(t)); }
            });
        }

        @JavascriptInterface
        public void cloudStart(String requestId) {
            executor.execute(() -> {
                try {
                    XiaomiCloudClient client = new XiaomiCloudClient();
                    cloudClient = client;
                    deliver(requestId, client.startQrLogin());
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
                } catch (Throwable t) { deliver(requestId, errorPayload(t)); }
            });
        }

        @JavascriptInterface
        public void openExternal(String url) {
            runOnUiThread(() -> {
                try {
                    Uri uri = Uri.parse(url);
                    String host = uri.getHost();
                    if (!"https".equalsIgnoreCase(uri.getScheme()) || host == null ||
                            !(host.equals("xiaomi.com") || host.endsWith(".xiaomi.com") || host.equals("mi.com") || host.endsWith(".mi.com"))) {
                        throw new IllegalArgumentException("URL não pertence a um domínio oficial Xiaomi");
                    }
                    startActivity(new Intent(Intent.ACTION_VIEW, uri));
                } catch (Throwable t) {
                    JSONObject out = errorPayload(t);
                    final String js = "window.onExternalOpenError(" + JSONObject.quote(out.optString("error", "Erro ao abrir página Xiaomi")) + ");";
                    webView.evaluateJavascript(js, null);
                }
            });
        }
    }
}
