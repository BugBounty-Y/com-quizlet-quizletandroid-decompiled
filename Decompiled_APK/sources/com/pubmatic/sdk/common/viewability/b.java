package com.pubmatic.sdk.common.viewability;

import android.content.Context;
import android.view.View;
import android.webkit.WebView;
import androidx.annotation.NonNull;

/* loaded from: classes2.dex */
public interface b extends d {
    @Override // com.pubmatic.sdk.common.viewability.d, com.pubmatic.sdk.common.viewability.i
    /* synthetic */ void addFriendlyObstructions(@NonNull View view, @NonNull h hVar);

    @Override // com.pubmatic.sdk.common.viewability.d
    /* synthetic */ void finishAdSession();

    @Override // com.pubmatic.sdk.common.viewability.d
    @NonNull
    /* synthetic */ String omSDKVersion();

    @Override // com.pubmatic.sdk.common.viewability.d
    /* synthetic */ void omidJsServiceScript(@NonNull Context context, @NonNull c cVar);

    @Override // com.pubmatic.sdk.common.viewability.d, com.pubmatic.sdk.common.viewability.i
    /* synthetic */ void removeFriendlyObstructions(View view);

    @Override // com.pubmatic.sdk.common.viewability.d
    /* synthetic */ void setTrackView(@NonNull View view);

    void signalAdEvent(@NonNull a aVar);

    void startAdSession(@NonNull WebView webView);
}
