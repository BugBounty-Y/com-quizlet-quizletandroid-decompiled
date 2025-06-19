package com.pubmatic.sdk.webrendering.mraid;

import android.annotation.TargetApi;
import android.content.Context;
import android.net.Uri;
import android.webkit.WebResourceRequest;
import android.webkit.WebResourceResponse;
import android.webkit.WebView;
import androidx.annotation.NonNull;
import com.pubmatic.sdk.common.log.POBLog;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Locale;

/* loaded from: classes2.dex */
public class f extends com.pubmatic.sdk.webrendering.ui.l {
    public f(@NonNull com.pubmatic.sdk.webrendering.ui.k kVar) {
        super(kVar);
    }

    private WebResourceResponse a(Context context) throws IOException {
        String fromAssets = com.pubmatic.sdk.common.utility.o.readFromAssets(context, "pob_mraid.js");
        if (fromAssets == null) {
            return null;
        }
        return new WebResourceResponse("text/javascript", StandardCharsets.UTF_8.name(), new ByteArrayInputStream("javascript:".concat(fromAssets).getBytes()));
    }

    private boolean b(String str) {
        return "mraid.js".equals(Uri.parse(str.toLowerCase(Locale.US)).getLastPathSegment());
    }

    @Override // android.webkit.WebViewClient
    public WebResourceResponse shouldInterceptRequest(WebView webView, String str) throws IOException {
        if (!b(str)) {
            return super.shouldInterceptRequest(webView, str);
        }
        POBLog.debug("POBMraidWebClient", "Injecting MRAID in webView via url", new Object[0]);
        WebResourceResponse webResourceResponseA = a(webView.getContext());
        return webResourceResponseA != null ? webResourceResponseA : super.shouldInterceptRequest(webView, str);
    }

    @Override // android.webkit.WebViewClient
    @TargetApi(21)
    public WebResourceResponse shouldInterceptRequest(WebView webView, WebResourceRequest webResourceRequest) throws IOException {
        if (b(webResourceRequest.getUrl().toString())) {
            POBLog.debug("POBMraidWebClient", "Injecting MRAID in webView via request", new Object[0]);
            WebResourceResponse webResourceResponseA = a(webView.getContext());
            return webResourceResponseA != null ? webResourceResponseA : super.shouldInterceptRequest(webView, webResourceRequest);
        }
        return super.shouldInterceptRequest(webView, webResourceRequest);
    }
}
