package com.sdk.growthbook.utils;

import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.StringsKt;
import okhttp3.sse.b;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public final class GBEventSourceListener extends b {
    private final boolean enableLogging;

    @NotNull
    private final GBEventSourceHandler handler;

    public GBEventSourceListener(@NotNull GBEventSourceHandler handler, boolean z) {
        Intrinsics.checkNotNullParameter(handler, "handler");
        this.handler = handler;
        this.enableLogging = z;
    }

    @Override // okhttp3.sse.b
    public void onClosed(@NotNull okhttp3.sse.a eventSource) {
        Intrinsics.checkNotNullParameter(eventSource, "eventSource");
        Intrinsics.checkNotNullParameter(eventSource, "eventSource");
        this.handler.onClose(eventSource);
    }

    @Override // okhttp3.sse.b
    public void onEvent(@NotNull okhttp3.sse.a eventSource, String str, String str2, @NotNull String data) {
        Intrinsics.checkNotNullParameter(eventSource, "eventSource");
        Intrinsics.checkNotNullParameter(data, "data");
        Intrinsics.checkNotNullParameter(eventSource, "eventSource");
        Intrinsics.checkNotNullParameter(data, "data");
        if (StringsKt.g0(data).toString().length() == 0) {
            return;
        }
        try {
            this.handler.onFeaturesResponse(data);
        } catch (Exception e) {
            if (this.enableLogging) {
                System.out.println(e);
            }
        }
    }
}
