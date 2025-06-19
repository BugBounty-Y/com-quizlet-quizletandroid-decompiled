package com.sdk.growthbook.model;

import android.support.v4.media.session.a;
import kotlin.Metadata;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public final class GBBoolean extends GBValue {
    private final boolean value;

    public GBBoolean(boolean z) {
        super(null);
        this.value = z;
    }

    public static /* synthetic */ GBBoolean copy$default(GBBoolean gBBoolean, boolean z, int i, Object obj) {
        if ((i & 1) != 0) {
            z = gBBoolean.value;
        }
        return gBBoolean.copy(z);
    }

    public final boolean component1() {
        return this.value;
    }

    @NotNull
    public final GBBoolean copy(boolean z) {
        return new GBBoolean(z);
    }

    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof GBBoolean) && this.value == ((GBBoolean) obj).value;
    }

    public final boolean getValue() {
        return this.value;
    }

    public int hashCode() {
        return Boolean.hashCode(this.value);
    }

    @NotNull
    public String toString() {
        return a.u(new StringBuilder("GBBoolean(value="), this.value, ')');
    }
}
