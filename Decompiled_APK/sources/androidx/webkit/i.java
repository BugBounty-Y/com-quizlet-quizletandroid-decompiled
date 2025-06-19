package androidx.webkit;

import android.net.Uri;
import android.webkit.WebView;
import androidx.appcompat.app.L;
import androidx.webkit.internal.p;
import androidx.webkit.internal.s;
import androidx.webkit.internal.u;
import java.util.Set;
import org.chromium.support_lib_boundary.WebViewProviderBoundaryInterface;

/* loaded from: classes.dex */
public abstract class i {
    public static final /* synthetic */ int a = 0;

    static {
        Uri.parse("*");
        Uri.parse("");
    }

    public static void a(WebView webView, String str, Set set, h hVar) {
        if (!s.e.b()) {
            throw s.a();
        }
        L lB = b(webView);
        String[] strArr = (String[]) set.toArray(new String[0]);
        p pVar = new p(0, false);
        pVar.b = hVar;
        ((WebViewProviderBoundaryInterface) lB.b).addWebMessageListener(str, strArr, new com.facebook.appevents.iap.h(pVar, 1));
    }

    public static L b(WebView webView) {
        WebViewProviderBoundaryInterface webViewProviderBoundaryInterfaceCreateWebView = u.a.createWebView(webView);
        L l = new L(13);
        l.b = webViewProviderBoundaryInterfaceCreateWebView;
        return l;
    }
}
