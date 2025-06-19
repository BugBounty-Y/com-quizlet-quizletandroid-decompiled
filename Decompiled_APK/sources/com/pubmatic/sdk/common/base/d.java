package com.pubmatic.sdk.common.base;

import android.view.View;
import androidx.annotation.NonNull;

/* loaded from: classes2.dex */
public interface d {
    void onAdExpired();

    void onAdImpression();

    void onAdInteractionStarted();

    void onAdInteractionStopped();

    void onAdReadyToRefresh(int i);

    void onAdRender(@NonNull View view, c cVar);

    void onAdRenderingFailed(@NonNull com.pubmatic.sdk.common.h hVar);

    void onAdUnload();

    void onLeavingApplication();

    void onRenderAdClick();

    void onRenderProcessGone();
}
