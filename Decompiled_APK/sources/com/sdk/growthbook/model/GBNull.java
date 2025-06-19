package com.sdk.growthbook.model;

import kotlin.Metadata;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public final class GBNull extends GBValue {

    @NotNull
    public static final GBNull INSTANCE = new GBNull();

    private GBNull() {
        super(null);
    }

    public boolean equals(Object obj) {
        return this == obj || (obj instanceof GBNull);
    }

    public int hashCode() {
        return -1439243580;
    }

    @NotNull
    public String toString() {
        return "GBNull";
    }
}
