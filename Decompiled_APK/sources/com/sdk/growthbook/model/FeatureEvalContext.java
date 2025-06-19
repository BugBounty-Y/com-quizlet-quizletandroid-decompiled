package com.sdk.growthbook.model;

import java.util.Set;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public final class FeatureEvalContext {

    @NotNull
    private final Set<String> evaluatedFeatures;
    private final String id;

    public FeatureEvalContext(String str, @NotNull Set<String> evaluatedFeatures) {
        Intrinsics.checkNotNullParameter(evaluatedFeatures, "evaluatedFeatures");
        this.id = str;
        this.evaluatedFeatures = evaluatedFeatures;
    }

    /* JADX WARN: Multi-variable type inference failed */
    public static /* synthetic */ FeatureEvalContext copy$default(FeatureEvalContext featureEvalContext, String str, Set set, int i, Object obj) {
        if ((i & 1) != 0) {
            str = featureEvalContext.id;
        }
        if ((i & 2) != 0) {
            set = featureEvalContext.evaluatedFeatures;
        }
        return featureEvalContext.copy(str, set);
    }

    public final String component1() {
        return this.id;
    }

    @NotNull
    public final Set<String> component2() {
        return this.evaluatedFeatures;
    }

    @NotNull
    public final FeatureEvalContext copy(String str, @NotNull Set<String> evaluatedFeatures) {
        Intrinsics.checkNotNullParameter(evaluatedFeatures, "evaluatedFeatures");
        return new FeatureEvalContext(str, evaluatedFeatures);
    }

    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof FeatureEvalContext)) {
            return false;
        }
        FeatureEvalContext featureEvalContext = (FeatureEvalContext) obj;
        return Intrinsics.b(this.id, featureEvalContext.id) && Intrinsics.b(this.evaluatedFeatures, featureEvalContext.evaluatedFeatures);
    }

    @NotNull
    public final Set<String> getEvaluatedFeatures() {
        return this.evaluatedFeatures;
    }

    public final String getId() {
        return this.id;
    }

    public int hashCode() {
        String str = this.id;
        return this.evaluatedFeatures.hashCode() + ((str == null ? 0 : str.hashCode()) * 31);
    }

    @NotNull
    public String toString() {
        return "FeatureEvalContext(id=" + this.id + ", evaluatedFeatures=" + this.evaluatedFeatures + ')';
    }
}
