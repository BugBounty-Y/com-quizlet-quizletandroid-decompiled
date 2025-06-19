package com.sdk.growthbook.model;

import java.util.List;
import kotlin.Metadata;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public final class GBFeature {
    private final GBValue defaultValue;
    private final List<GBFeatureRule> rules;

    /* JADX WARN: Multi-variable type inference failed */
    public GBFeature() {
        this(null, 0 == true ? 1 : 0, 3, 0 == true ? 1 : 0);
    }

    /* JADX WARN: Multi-variable type inference failed */
    public static /* synthetic */ GBFeature copy$default(GBFeature gBFeature, GBValue gBValue, List list, int i, Object obj) {
        if ((i & 1) != 0) {
            gBValue = gBFeature.defaultValue;
        }
        if ((i & 2) != 0) {
            list = gBFeature.rules;
        }
        return gBFeature.copy(gBValue, list);
    }

    public final GBValue component1() {
        return this.defaultValue;
    }

    public final List<GBFeatureRule> component2() {
        return this.rules;
    }

    @NotNull
    public final GBFeature copy(GBValue gBValue, List<GBFeatureRule> list) {
        return new GBFeature(gBValue, list);
    }

    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof GBFeature)) {
            return false;
        }
        GBFeature gBFeature = (GBFeature) obj;
        return Intrinsics.b(this.defaultValue, gBFeature.defaultValue) && Intrinsics.b(this.rules, gBFeature.rules);
    }

    public final GBValue getDefaultValue() {
        return this.defaultValue;
    }

    public final List<GBFeatureRule> getRules() {
        return this.rules;
    }

    public int hashCode() {
        GBValue gBValue = this.defaultValue;
        int iHashCode = (gBValue == null ? 0 : gBValue.hashCode()) * 31;
        List<GBFeatureRule> list = this.rules;
        return iHashCode + (list != null ? list.hashCode() : 0);
    }

    @NotNull
    public String toString() {
        return "GBFeature(defaultValue=" + this.defaultValue + ", rules=" + this.rules + ')';
    }

    public GBFeature(GBValue gBValue, List<GBFeatureRule> list) {
        this.defaultValue = gBValue;
        this.rules = list;
    }

    public /* synthetic */ GBFeature(GBValue gBValue, List list, int i, DefaultConstructorMarker defaultConstructorMarker) {
        this((i & 1) != 0 ? null : gBValue, (i & 2) != 0 ? null : list);
    }
}
