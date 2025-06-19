package com.pubmatic.sdk.webrendering.mraid;

import android.view.View;
import androidx.annotation.NonNull;

/* loaded from: classes2.dex */
public interface w extends com.pubmatic.sdk.common.viewability.i {
    @Override // com.pubmatic.sdk.common.viewability.i
    /* synthetic */ void addFriendlyObstructions(@NonNull View view, @NonNull com.pubmatic.sdk.common.viewability.h hVar);

    boolean isUserInteracted(boolean z);

    void onAdInteractionStarted();

    void onAdInteractionStopped();

    void onAdUnload();

    void onAdViewChanged(View view);

    void onLeavingApplication();

    void onMRAIDAdClick();

    void onOpen(String str);

    @Override // com.pubmatic.sdk.common.viewability.i
    /* synthetic */ void removeFriendlyObstructions(View view);
}
