package com.sdk.growthbook.utils;

import kotlin.Metadata;

@Metadata
/* loaded from: classes3.dex */
public interface GBEventSourceHandler {
    void onClose(okhttp3.sse.a aVar);

    void onFeaturesResponse(String str);
}
