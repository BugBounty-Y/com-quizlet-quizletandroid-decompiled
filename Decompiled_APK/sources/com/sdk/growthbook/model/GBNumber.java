package com.sdk.growthbook.model;

import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public final class GBNumber extends GBValue {

    @NotNull
    private final Number value;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public GBNumber(@NotNull Number value) {
        super(null);
        Intrinsics.checkNotNullParameter(value, "value");
        this.value = value;
    }

    public static /* synthetic */ GBNumber copy$default(GBNumber gBNumber, Number number, int i, Object obj) {
        if ((i & 1) != 0) {
            number = gBNumber.value;
        }
        return gBNumber.copy(number);
    }

    @NotNull
    public final Number component1() {
        return this.value;
    }

    @NotNull
    public final GBNumber copy(@NotNull Number value) {
        Intrinsics.checkNotNullParameter(value, "value");
        return new GBNumber(value);
    }

    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof GBNumber) && Intrinsics.b(this.value, ((GBNumber) obj).value);
    }

    @NotNull
    public final Number getValue() {
        return this.value;
    }

    public int hashCode() {
        return this.value.hashCode();
    }

    @NotNull
    public String toString() {
        return "GBNumber(value=" + this.value + ')';
    }
}
