package com.litemini.shipments;

import android.app.Activity;
import android.app.AlertDialog;
import android.app.DownloadManager;
import android.content.ActivityNotFoundException;
import android.content.ContentValues;
import android.content.Context;
import android.content.DialogInterface;
import android.content.Intent;
import android.content.SharedPreferences;
import android.graphics.Color;
import android.net.ConnectivityManager;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.os.Environment;
import android.provider.MediaStore;
import android.text.InputType;
import android.util.Base64;
import android.view.Gravity;
import android.view.KeyEvent;
import android.view.View;
import android.view.ViewGroup;
import android.webkit.CookieManager;
import android.webkit.JavascriptInterface;
import android.webkit.URLUtil;
import android.webkit.ValueCallback;
import android.webkit.WebChromeClient;
import android.webkit.WebResourceError;
import android.webkit.WebResourceRequest;
import android.webkit.WebSettings;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.TextView;
import android.widget.Toast;

import java.io.File;
import java.io.FileOutputStream;
import java.io.OutputStream;
import java.util.HashMap;
import java.util.Map;

/**
 * Thin Android shell: opens the web app (GitHub Pages link), keeps the login, handles file pick / save,
 * and has an "update" button that clears the cache and reloads, so nothing is ever re-installed.
 */
public class MainActivity extends Activity {
    private static final String DEFAULT_URL = "https://cheekaya9.github.io/litemini/";
    private static final int REQ_FILE = 1;

    private WebView web;
    private SharedPreferences prefs;
    private String appUrl = "";
    private ValueCallback<Uri[]> fileCallback;
    private boolean errorShown = false;

    // ---------- UI ----------
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        prefs = getSharedPreferences("shipments", MODE_PRIVATE);
        appUrl = prefs.getString("url", "");

        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setLayoutDirection(View.LAYOUT_DIRECTION_RTL);
        root.setBackgroundColor(Color.parseColor("#071d44"));

        LinearLayout bar = new LinearLayout(this);
        bar.setOrientation(LinearLayout.HORIZONTAL);
        bar.setGravity(Gravity.CENTER_VERTICAL);
        bar.setBackgroundColor(Color.parseColor("#0b2a5b"));
        int p = dp(6);
        bar.setPadding(p, p, p, p);

        TextView title = new TextView(this);
        title.setText("نظام الشحنات");
        title.setTextColor(Color.WHITE);
        title.setTextSize(16);
        title.setPadding(dp(8), 0, dp(8), 0);
        bar.addView(title, new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));

        Button update = barButton("⟳ تحديث", "#22c55e");
        update.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) { refreshApp(true); }
        });
        Button link = barButton("الرابط", "#3b5b94");
        link.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) { askForUrl(); }
        });
        bar.addView(update);
        bar.addView(link);
        root.addView(bar, new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT));

        web = new WebView(this);
        root.addView(web, new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, 0, 1f));
        setContentView(root);

        setupWebView();

        if (appUrl.isEmpty()) askForUrl(); else refreshApp(false);
    }

    private Button barButton(String text, String color) {
        Button b = new Button(this);
        b.setText(text);
        b.setTextColor(Color.WHITE);
        b.setTextSize(13);
        b.setAllCaps(false);
        b.setBackgroundColor(Color.parseColor(color));
        b.setMinHeight(0);
        b.setMinimumHeight(dp(36));
        b.setPadding(dp(14), 0, dp(14), 0);
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.WRAP_CONTENT, dp(36));
        lp.setMargins(dp(4), 0, dp(4), 0);
        b.setLayoutParams(lp);
        return b;
    }

    private int dp(int v) { return (int) (v * getResources().getDisplayMetrics().density + 0.5f); }

    // ---------- WebView ----------
    private void setupWebView() {
        WebSettings s = web.getSettings();
        s.setJavaScriptEnabled(true);
        s.setDomStorageEnabled(true);          // keeps the login (localStorage)
        s.setDatabaseEnabled(true);
        s.setAllowFileAccess(false);
        s.setAllowContentAccess(true);
        s.setMediaPlaybackRequiresUserGesture(true);
        s.setBuiltInZoomControls(false);
        s.setSupportZoom(false);
        s.setLoadWithOverviewMode(true);
        s.setUseWideViewPort(true);
        s.setCacheMode(WebSettings.LOAD_DEFAULT);
        CookieManager.getInstance().setAcceptCookie(true);

        web.addJavascriptInterface(new Bridge(), "AndroidBridge");

        web.setWebViewClient(new WebViewClient() {
            @Override
            public boolean shouldOverrideUrlLoading(WebView v, WebResourceRequest req) {
                return handleUrl(req.getUrl());
            }
            @Override
            public void onPageStarted(WebView v, String url, android.graphics.Bitmap icon) { errorShown = false; }
            @Override
            public void onPageFinished(WebView v, String url) { v.evaluateJavascript(DOWNLOAD_HOOK, null); }
            @Override
            @SuppressWarnings("deprecation")
            public void onReceivedError(WebView v, int code, String desc, String failingUrl) {
                if (Build.VERSION.SDK_INT < 23 && failingUrl != null && failingUrl.equals(appUrl) && !errorShown) { errorShown = true; showOffline(); }
            }
            @Override
            public void onReceivedError(WebView v, WebResourceRequest req, WebResourceError err) {
                if (req.isForMainFrame() && !errorShown) { errorShown = true; showOffline(); }
            }
        });

        web.setWebChromeClient(new WebChromeClient() {
            @Override
            public boolean onShowFileChooser(WebView v, ValueCallback<Uri[]> cb, FileChooserParams params) {
                if (fileCallback != null) fileCallback.onReceiveValue(null);
                fileCallback = cb;
                try {
                    startActivityForResult(params.createIntent(), REQ_FILE);
                } catch (ActivityNotFoundException e) {
                    fileCallback = null;
                    Toast.makeText(MainActivity.this, "تعذّر فتح اختيار الملفات", Toast.LENGTH_SHORT).show();
                    return false;
                }
                return true;
            }
        });

        web.setDownloadListener(new android.webkit.DownloadListener() {
            @Override
            public void onDownloadStart(String url, String ua, String cd, String mime, long len) {
                if (url.startsWith("blob:") || url.startsWith("data:")) return; // handled by the JS hook
                try {
                    DownloadManager.Request r = new DownloadManager.Request(Uri.parse(url));
                    String name = URLUtil.guessFileName(url, cd, mime);
                    r.setMimeType(mime);
                    r.addRequestHeader("cookie", CookieManager.getInstance().getCookie(url));
                    r.setNotificationVisibility(DownloadManager.Request.VISIBILITY_VISIBLE_NOTIFY_COMPLETED);
                    r.setDestinationInExternalFilesDir(MainActivity.this, Environment.DIRECTORY_DOWNLOADS, name);
                    ((DownloadManager) getSystemService(Context.DOWNLOAD_SERVICE)).enqueue(r);
                    Toast.makeText(MainActivity.this, "بدأ التحميل: " + name, Toast.LENGTH_SHORT).show();
                } catch (Exception e) {
                    Toast.makeText(MainActivity.this, "تعذّر التحميل", Toast.LENGTH_SHORT).show();
                }
            }
        });
    }

    /** Clears the HTTP cache and reloads, so the newest version of the app is always shown. */
    private void refreshApp(boolean toast) {
        if (appUrl.isEmpty()) { askForUrl(); return; }
        if (!isOnline()) { showOffline(); return; }
        errorShown = false;
        web.clearCache(true);
        Map<String, String> h = new HashMap<String, String>();
        h.put("Cache-Control", "no-cache");
        h.put("Pragma", "no-cache");
        web.loadUrl(appUrl, h);
        if (toast) Toast.makeText(this, "جاري تحميل آخر تحديث…", Toast.LENGTH_SHORT).show();
    }

    private boolean isOnline() {
        try {
            ConnectivityManager cm = (ConnectivityManager) getSystemService(Context.CONNECTIVITY_SERVICE);
            return cm.getActiveNetworkInfo() != null && cm.getActiveNetworkInfo().isConnected();
        } catch (Exception e) { return true; }
    }

    private boolean handleUrl(Uri u) {
        String scheme = u.getScheme() == null ? "" : u.getScheme().toLowerCase();
        if (scheme.equals("blob") || scheme.equals("about") || scheme.equals("data")) return false;
        try {
            Uri base = Uri.parse(appUrl);
            if ((scheme.equals("http") || scheme.equals("https")) && base.getHost() != null
                    && base.getHost().equalsIgnoreCase(u.getHost())) return false;
            startActivity(new Intent(Intent.ACTION_VIEW, u));
        } catch (Exception ignored) { }
        return true;
    }

    private void showOffline() {
        new AlertDialog.Builder(this)
                .setTitle("تعذّر الاتصال")
                .setMessage("اتأكد من الإنترنت ثم جرّب تاني.")
                .setPositiveButton("إعادة المحاولة", new DialogInterface.OnClickListener() {
                    public void onClick(DialogInterface d, int w) { errorShown = false; refreshApp(false); }
                })
                .setNeutralButton("تغيير الرابط", new DialogInterface.OnClickListener() {
                    public void onClick(DialogInterface d, int w) { askForUrl(); }
                })
                .setNegativeButton("إغلاق", null)
                .show();
    }

    // ---------- link dialog ----------
    private void askForUrl() {
        final EditText in = new EditText(this);
        in.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_VARIATION_URI);
        in.setSingleLine(true);
        in.setLayoutDirection(View.LAYOUT_DIRECTION_LTR);
        in.setText(appUrl.isEmpty() ? DEFAULT_URL : appUrl);
        in.setSelectAllOnFocus(true);
        final AlertDialog.Builder b = new AlertDialog.Builder(this)
                .setTitle("رابط التطبيق")
                .setMessage("اكتب رابط الموقع (أو رابط مستودع GitHub)")
                .setView(in)
                .setPositiveButton("حفظ وفتح", null)
                .setNegativeButton("إلغاء", null);
        final AlertDialog d = b.create();
        d.setOnShowListener(new DialogInterface.OnShowListener() {
            public void onShow(DialogInterface x) {
                d.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener(new View.OnClickListener() {
                    public void onClick(View v) {
                        String r = normalizeUrl(in.getText().toString());
                        if (r == null) { in.setError("الرابط غير صحيح"); return; }
                        appUrl = r;
                        prefs.edit().putString("url", appUrl).apply();
                        d.dismiss();
                        refreshApp(false);
                    }
                });
            }
        });
        d.show();
    }

    /** https link, or a github.com/owner/repo link converted to its GitHub Pages address. */
    static String normalizeUrl(String in) {
        String s = in == null ? "" : in.trim();
        if (s.isEmpty() || s.contains(" ")) return null;
        if (!s.matches("^[a-zA-Z][a-zA-Z0-9+.-]*://.*")) s = "https://" + s;
        Uri u = Uri.parse(s);
        String host = u.getHost() == null ? "" : u.getHost().toLowerCase();
        if (!(s.startsWith("https://") || s.startsWith("http://")) || !host.contains(".")) return null;
        if (host.equals("github.com") || host.equals("www.github.com")) {
            java.util.List<String> parts = new java.util.ArrayList<String>();
            for (String seg : u.getPathSegments()) if (!seg.isEmpty()) parts.add(seg);
            if (parts.size() < 2) return null;
            String owner = parts.get(0).toLowerCase();
            String repo = parts.get(1).replaceAll("(?i)\\.git$", "");
            String pages = owner + ".github.io";
            return repo.equalsIgnoreCase(pages) ? "https://" + pages + "/" : "https://" + pages + "/" + repo + "/";
        }
        String out = u.buildUpon().fragment(null).build().toString();
        if (u.getPath() == null || u.getPath().isEmpty()) out += "/";
        return out;
    }

    // ---------- file chooser result ----------
    @Override
    protected void onActivityResult(int req, int res, Intent data) {
        if (req == REQ_FILE && fileCallback != null) {
            Uri[] r = null;
            if (res == RESULT_OK && data != null) r = WebChromeClient.FileChooserParams.parseResult(res, data);
            fileCallback.onReceiveValue(r);
            fileCallback = null;
            return;
        }
        super.onActivityResult(req, res, data);
    }

    @Override
    public boolean onKeyDown(int code, KeyEvent e) {
        if (code == KeyEvent.KEYCODE_BACK && web.canGoBack()) { web.goBack(); return true; }
        return super.onKeyDown(code, e);
    }

    // ---------- saving files produced by the page (Excel / zip via blob:) ----------
    /** Page -> app: hands over files that the page creates in memory (blob:) so they can be saved. */
    private static final String DOWNLOAD_HOOK =
        "(function(){if(window.__dlHook)return;window.__dlHook=1;" +
        "function send(a){try{var h=a.href;var name=a.download||'file';" +
        "fetch(h).then(function(r){return r.blob();}).then(function(b){var fr=new FileReader();" +
        "fr.onloadend=function(){var d=String(fr.result);AndroidBridge.saveFile(name,b.type||'application/octet-stream',d.substring(d.indexOf(',')+1));};" +
        "fr.readAsDataURL(b);});}catch(e){}}" +
        "function isDl(a){return a&&a.download!==undefined&&a.hasAttribute&&a.hasAttribute('download')&&/^(blob:|data:)/.test(a.href||'');}" +
        "var oc=HTMLAnchorElement.prototype.click;" +
        "HTMLAnchorElement.prototype.click=function(){if(isDl(this)){send(this);return;}return oc.apply(this,arguments);};" +
        "document.addEventListener('click',function(e){var a=e.target&&e.target.closest?e.target.closest('a'):null;" +
        "if(isDl(a)){e.preventDefault();send(a);}},true);})();";

    private class Bridge {
        @JavascriptInterface
        public void saveFile(final String name, final String mime, final String base64) {
            runOnUiThread(new Runnable() { public void run() { storeFile(name, mime, base64); } });
        }
    }

    private void storeFile(String name, String mime, String base64) {
        try {
            byte[] bytes = Base64.decode(base64, Base64.DEFAULT);
            String safe = name.replaceAll("[\\\\/:*?\"<>|]", "_");
            Uri uri = null;
            String where;
            if (Build.VERSION.SDK_INT >= 29) {
                ContentValues cv = new ContentValues();
                cv.put(MediaStore.Downloads.DISPLAY_NAME, safe);
                cv.put(MediaStore.Downloads.MIME_TYPE, mime);
                cv.put(MediaStore.Downloads.RELATIVE_PATH, Environment.DIRECTORY_DOWNLOADS);
                uri = getContentResolver().insert(MediaStore.Downloads.EXTERNAL_CONTENT_URI, cv);
                if (uri == null) throw new Exception("insert failed");
                OutputStream os = getContentResolver().openOutputStream(uri);
                os.write(bytes);
                os.close();
                where = "مجلد التنزيلات (Downloads)";
            } else {
                File dir = getExternalFilesDir(Environment.DIRECTORY_DOWNLOADS);
                if (dir == null) dir = getFilesDir();
                dir.mkdirs();
                File f = new File(dir, safe);
                FileOutputStream os = new FileOutputStream(f);
                os.write(bytes);
                os.close();
                where = f.getParent();
            }
            final Uri openUri = uri;
            final String openMime = mime;
            AlertDialog.Builder b = new AlertDialog.Builder(this)
                    .setTitle("تم حفظ الملف")
                    .setMessage(safe + "\n\n" + where)
                    .setNegativeButton("تم", null);
            if (openUri != null) {
                b.setPositiveButton("فتح", new DialogInterface.OnClickListener() {
                    public void onClick(DialogInterface d, int w) {
                        try {
                            Intent i = new Intent(Intent.ACTION_VIEW);
                            i.setDataAndType(openUri, openMime);
                            i.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION);
                            startActivity(i);
                        } catch (Exception e) {
                            Toast.makeText(MainActivity.this, "لا يوجد تطبيق لفتح هذا الملف", Toast.LENGTH_SHORT).show();
                        }
                    }
                });
            }
            b.show();
        } catch (Exception e) {
            new AlertDialog.Builder(this).setTitle("تعذّر حفظ الملف")
                    .setMessage("جرّب تاني، واتأكد إن فيه مساحة فاضية.").setPositiveButton("حسنًا", null).show();
        }
    }
}
