package com.pubmatic.sdk.video.renderer;

import androidx.annotation.NonNull;

/* loaded from: classes2.dex */
public interface c extends com.pubmatic.sdk.common.ui.a {
    @Override // com.pubmatic.sdk.common.ui.a
    void destroy();

    @Override // com.pubmatic.sdk.common.ui.a
    /* synthetic */ void invalidateExpiration();

    void proceedAdSkip(boolean z);

    @Override // com.pubmatic.sdk.common.ui.a
    /* synthetic */ void renderAd(@NonNull com.pubmatic.sdk.common.base.c cVar);

    @Override // com.pubmatic.sdk.common.ui.a
    /* synthetic */ void setAdRendererListener(com.pubmatic.sdk.common.base.d dVar);

    void setVideoRenderingListener(d dVar);

    void setVideoSkipEventListener(e eVar);
}
