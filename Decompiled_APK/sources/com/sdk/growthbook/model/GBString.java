package com.sdk.growthbook.model;

import androidx.compose.animation.d0;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public final class GBString extends GBValue {

    @NotNull
    private final String value;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public GBString(@NotNull String value) {
        super(null);
        Intrinsics.checkNotNullParameter(value, "value");
        this.value = value;
    }

    public static /* synthetic */ GBString copy$default(GBString gBString, String str, int i, Object obj) {
        if ((i & 1) != 0) {
            str = gBString.value;
        }
        return gBString.copy(str);
    }

    @NotNull
    public final String component1() {
        return this.value;
    }

    @NotNull
    public final GBString copy(@NotNull String value) {
        Intrinsics.checkNotNullParameter(value, "value");
        return new GBString(value);
    }

    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof GBString) && Intrinsics.b(this.value, ((GBString) obj).value);
    }

    @NotNull
    public final String getValue() {
        return this.value;
    }

    public int hashCode() {
        return this.value.hashCode();
    }

    @NotNull
    public String toString() {
        return d0.r(new StringBuilder("GBString(value="), this.value, ')');
    }
}
