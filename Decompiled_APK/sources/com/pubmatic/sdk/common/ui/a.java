package com.pubmatic.sdk.common.ui;

import androidx.annotation.NonNull;

/* loaded from: classes2.dex */
public interface a {
    void destroy();

    void invalidateExpiration();

    void renderAd(@NonNull com.pubmatic.sdk.common.base.c cVar);

    void setAdRendererListener(com.pubmatic.sdk.common.base.d dVar);
}
