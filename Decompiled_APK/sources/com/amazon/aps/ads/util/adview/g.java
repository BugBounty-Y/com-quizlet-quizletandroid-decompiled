package com.amazon.aps.ads.util.adview;

import android.content.Context;
import android.webkit.WebView;

/* loaded from: classes.dex */
public interface g {
    Context getAdViewContext();

    boolean isTwoPartExpand();

    void onAdLeftApplication();

    void onCrash(WebView webView, StringBuilder sb, String str);

    void onLoadError();

    void onPageFinished(String str, WebView webView);
}
