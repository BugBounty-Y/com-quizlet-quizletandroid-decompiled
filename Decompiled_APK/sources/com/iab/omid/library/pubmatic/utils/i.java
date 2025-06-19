package com.iab.omid.library.pubmatic.utils;

import android.webkit.WebView;
import androidx.annotation.NonNull;
import androidx.webkit.internal.s;
import java.util.Set;
import org.chromium.support_lib_boundary.WebViewProviderBoundaryInterface;

/* loaded from: classes2.dex */
public class i {
    public void a(@NonNull WebView webView, @NonNull String str, @NonNull Set<String> set, @NonNull androidx.webkit.h hVar) {
        androidx.webkit.i.a(webView, str, set, hVar);
    }

    public void a(@NonNull WebView webView, @NonNull String str) {
        int i = androidx.webkit.i.a;
        if (!s.e.b()) {
            throw s.a();
        }
        ((WebViewProviderBoundaryInterface) androidx.webkit.i.b(webView).b).removeWebMessageListener(str);
    }
}
