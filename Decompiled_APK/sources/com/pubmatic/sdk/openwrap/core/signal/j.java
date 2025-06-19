package com.pubmatic.sdk.openwrap.core.signal;

import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

/* loaded from: classes2.dex */
public final class j {

    @NotNull
    public static final j INSTANCE = new j();

    private j() {
    }

    @NotNull
    public static final i getSignalGenerator(@NotNull g biddingHost) {
        Intrinsics.checkNotNullParameter(biddingHost, "biddingHost");
        return new e();
    }
}
