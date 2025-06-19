package com.sdk.growthbook.utils;

import com.sdk.growthbook.model.GBValue;
import java.util.Map;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public final class GBRemoteEvalParams {

    @NotNull
    private final Map<String, Object> attributes;

    @NotNull
    private final Map<String, GBValue> forcedFeatures;

    @NotNull
    private final Map<String, Object> forcedVariations;

    /* JADX WARN: Multi-variable type inference failed */
    public GBRemoteEvalParams(@NotNull Map<String, ? extends Object> attributes, @NotNull Map<String, ? extends GBValue> forcedFeatures, @NotNull Map<String, ? extends Object> forcedVariations) {
        Intrinsics.checkNotNullParameter(attributes, "attributes");
        Intrinsics.checkNotNullParameter(forcedFeatures, "forcedFeatures");
        Intrinsics.checkNotNullParameter(forcedVariations, "forcedVariations");
        this.attributes = attributes;
        this.forcedFeatures = forcedFeatures;
        this.forcedVariations = forcedVariations;
    }

    /* JADX WARN: Multi-variable type inference failed */
    public static /* synthetic */ GBRemoteEvalParams copy$default(GBRemoteEvalParams gBRemoteEvalParams, Map map, Map map2, Map map3, int i, Object obj) {
        if ((i & 1) != 0) {
            map = gBRemoteEvalParams.attributes;
        }
        if ((i & 2) != 0) {
            map2 = gBRemoteEvalParams.forcedFeatures;
        }
        if ((i & 4) != 0) {
            map3 = gBRemoteEvalParams.forcedVariations;
        }
        return gBRemoteEvalParams.copy(map, map2, map3);
    }

    @NotNull
    public final Map<String, Object> component1() {
        return this.attributes;
    }

    @NotNull
    public final Map<String, GBValue> component2() {
        return this.forcedFeatures;
    }

    @NotNull
    public final Map<String, Object> component3() {
        return this.forcedVariations;
    }

    @NotNull
    public final GBRemoteEvalParams copy(@NotNull Map<String, ? extends Object> attributes, @NotNull Map<String, ? extends GBValue> forcedFeatures, @NotNull Map<String, ? extends Object> forcedVariations) {
        Intrinsics.checkNotNullParameter(attributes, "attributes");
        Intrinsics.checkNotNullParameter(forcedFeatures, "forcedFeatures");
        Intrinsics.checkNotNullParameter(forcedVariations, "forcedVariations");
        return new GBRemoteEvalParams(attributes, forcedFeatures, forcedVariations);
    }

    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof GBRemoteEvalParams)) {
            return false;
        }
        GBRemoteEvalParams gBRemoteEvalParams = (GBRemoteEvalParams) obj;
        return Intrinsics.b(this.attributes, gBRemoteEvalParams.attributes) && Intrinsics.b(this.forcedFeatures, gBRemoteEvalParams.forcedFeatures) && Intrinsics.b(this.forcedVariations, gBRemoteEvalParams.forcedVariations);
    }

    @NotNull
    public final Map<String, Object> getAttributes() {
        return this.attributes;
    }

    @NotNull
    public final Map<String, GBValue> getForcedFeatures() {
        return this.forcedFeatures;
    }

    @NotNull
    public final Map<String, Object> getForcedVariations() {
        return this.forcedVariations;
    }

    public int hashCode() {
        return this.forcedVariations.hashCode() + assistantMode.refactored.a.d(this.attributes.hashCode() * 31, 31, this.forcedFeatures);
    }

    @NotNull
    public String toString() {
        return "GBRemoteEvalParams(attributes=" + this.attributes + ", forcedFeatures=" + this.forcedFeatures + ", forcedVariations=" + this.forcedVariations + ')';
    }
}
