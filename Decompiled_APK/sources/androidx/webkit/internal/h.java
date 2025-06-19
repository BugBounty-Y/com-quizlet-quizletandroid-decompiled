package androidx.webkit.internal;

import android.webkit.WebSettings;
import android.webkit.WebView;
import android.webkit.WebViewRenderProcess;
import android.webkit.WebViewRenderProcessClient;
import androidx.annotation.NonNull;
import java.util.concurrent.Executor;

/* loaded from: classes.dex */
public abstract class h {
    @Deprecated
    public static int a(@NonNull WebSettings webSettings) {
        return webSettings.getForceDark();
    }

    public static WebViewRenderProcess b(@NonNull WebView webView) {
        return webView.getWebViewRenderProcess();
    }

    public static WebViewRenderProcessClient c(@NonNull WebView webView) {
        return webView.getWebViewRenderProcessClient();
    }

    @Deprecated
    public static void d(@NonNull WebSettings webSettings, int i) {
        webSettings.setForceDark(i);
    }

    public static void e(@NonNull WebView webView, androidx.webkit.j jVar) {
        webView.setWebViewRenderProcessClient(null);
    }

    public static void f(@NonNull WebView webView, @NonNull Executor executor, androidx.webkit.j jVar) {
        webView.setWebViewRenderProcessClient(executor, null);
    }

    public static boolean g(@NonNull WebViewRenderProcess webViewRenderProcess) {
        return webViewRenderProcess.terminate();
    }
}
