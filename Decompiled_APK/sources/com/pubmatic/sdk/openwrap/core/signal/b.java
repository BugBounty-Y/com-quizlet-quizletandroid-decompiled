package com.pubmatic.sdk.openwrap.core.signal;

import com.pubmatic.sdk.openwrap.core.p;
import com.pubmatic.sdk.openwrap.core.v;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

/* loaded from: classes2.dex */
public final class b {

    @NotNull
    public static final b INSTANCE = new b();

    private b() {
    }

    public static final v getRequest(@NotNull p impression) {
        Intrinsics.checkNotNullParameter(impression, "impression");
        return v.createInstance("NA", 0, impression);
    }
}
