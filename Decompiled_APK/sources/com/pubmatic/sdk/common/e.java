package com.pubmatic.sdk.common;

import android.content.Context;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.StringsKt;
import org.jetbrains.annotations.NotNull;

/* loaded from: classes2.dex */
public final class e implements d {

    @NotNull
    public static final e INSTANCE = new e();
    private static boolean a;

    private e() {
    }

    @Override // com.pubmatic.sdk.common.d
    public void initialize(@NotNull Context context, @NotNull b sdkConfig, @NotNull c listener) {
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(sdkConfig, "sdkConfig");
        Intrinsics.checkNotNullParameter(listener, "listener");
        if (!StringsKt.O(sdkConfig.getPublisherId()) && !sdkConfig.getProfileIds().isEmpty()) {
            a = true;
            listener.onSuccess();
        } else {
            a = false;
            new h(1013, "One or more invalid mandatory config parameters. Please verify Publisher Id & Profile Ids");
            listener.a();
        }
    }

    @Override // com.pubmatic.sdk.common.d
    public boolean isInitialized() {
        return a;
    }
}
