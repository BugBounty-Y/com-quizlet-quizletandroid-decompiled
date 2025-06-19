package androidx.webkit.internal;

import android.content.pm.PackageInfo;
import android.webkit.WebChromeClient;
import android.webkit.WebSettings;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import androidx.annotation.NonNull;

/* loaded from: classes.dex */
public abstract class e {
    @NonNull
    public static PackageInfo a() {
        return WebView.getCurrentWebViewPackage();
    }

    public static boolean b(@NonNull WebSettings webSettings) {
        return webSettings.getSafeBrowsingEnabled();
    }

    public static WebChromeClient c(@NonNull WebView webView) {
        return webView.getWebChromeClient();
    }

    public static WebViewClient d(@NonNull WebView webView) {
        return webView.getWebViewClient();
    }

    public static void e(@NonNull WebSettings webSettings, boolean z) {
        webSettings.setSafeBrowsingEnabled(z);
    }
}
