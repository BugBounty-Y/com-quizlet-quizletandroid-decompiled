package com.pubmatic.sdk.webrendering.ui;

import android.webkit.WebView;
import androidx.annotation.NonNull;

/* loaded from: classes2.dex */
public interface j {
    void onPageFinished(@NonNull WebView webView);

    void onReceivedError(@NonNull com.pubmatic.sdk.common.h hVar);

    boolean shouldOverrideUrlLoading(String str);
}
