package com.pubmatic.sdk.common.ui;

import androidx.annotation.NonNull;

/* loaded from: classes2.dex */
public interface g {
    void destroy();

    void renderAd(@NonNull com.pubmatic.sdk.common.base.c cVar);

    void setAdRendererListener(f fVar);

    void setVideoAdEventListener(h hVar);

    void show(int i);
}
