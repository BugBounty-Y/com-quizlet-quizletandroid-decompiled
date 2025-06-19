package com.sdk.growthbook.model;

import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public final class GBValuesKt {
    @NotNull
    public static final GBBoolean toGbBoolean(boolean z) {
        return new GBBoolean(z);
    }

    @NotNull
    public static final GBNumber toGbNumber(@NotNull Number number) {
        Intrinsics.checkNotNullParameter(number, "<this>");
        return new GBNumber(number);
    }

    @NotNull
    public static final GBString toGbString(@NotNull String str) {
        Intrinsics.checkNotNullParameter(str, "<this>");
        return new GBString(str);
    }
}
