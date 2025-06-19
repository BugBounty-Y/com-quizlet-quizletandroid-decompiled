package com.sdk.growthbook.model;

import androidx.compose.animation.d0;
import kotlin.Metadata;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public final class GBFeatureResult {
    private final GBExperiment experiment;
    private final GBExperimentResult experimentResult;
    private final GBValue gbValue;
    private final boolean off;
    private final boolean on;

    @NotNull
    private final GBFeatureSource source;

    public GBFeatureResult(GBValue gBValue, boolean z, boolean z2, @NotNull GBFeatureSource source, GBExperiment gBExperiment, GBExperimentResult gBExperimentResult) {
        Intrinsics.checkNotNullParameter(source, "source");
        this.gbValue = gBValue;
        this.on = z;
        this.off = z2;
        this.source = source;
        this.experiment = gBExperiment;
        this.experimentResult = gBExperimentResult;
    }

    public static /* synthetic */ GBFeatureResult copy$default(GBFeatureResult gBFeatureResult, GBValue gBValue, boolean z, boolean z2, GBFeatureSource gBFeatureSource, GBExperiment gBExperiment, GBExperimentResult gBExperimentResult, int i, Object obj) {
        if ((i & 1) != 0) {
            gBValue = gBFeatureResult.gbValue;
        }
        if ((i & 2) != 0) {
            z = gBFeatureResult.on;
        }
        if ((i & 4) != 0) {
            z2 = gBFeatureResult.off;
        }
        if ((i & 8) != 0) {
            gBFeatureSource = gBFeatureResult.source;
        }
        if ((i & 16) != 0) {
            gBExperiment = gBFeatureResult.experiment;
        }
        if ((i & 32) != 0) {
            gBExperimentResult = gBFeatureResult.experimentResult;
        }
        GBExperiment gBExperiment2 = gBExperiment;
        GBExperimentResult gBExperimentResult2 = gBExperimentResult;
        return gBFeatureResult.copy(gBValue, z, z2, gBFeatureSource, gBExperiment2, gBExperimentResult2);
    }

    public final GBValue component1() {
        return this.gbValue;
    }

    public final boolean component2() {
        return this.on;
    }

    public final boolean component3() {
        return this.off;
    }

    @NotNull
    public final GBFeatureSource component4() {
        return this.source;
    }

    public final GBExperiment component5() {
        return this.experiment;
    }

    public final GBExperimentResult component6() {
        return this.experimentResult;
    }

    @NotNull
    public final GBFeatureResult copy(GBValue gBValue, boolean z, boolean z2, @NotNull GBFeatureSource source, GBExperiment gBExperiment, GBExperimentResult gBExperimentResult) {
        Intrinsics.checkNotNullParameter(source, "source");
        return new GBFeatureResult(gBValue, z, z2, source, gBExperiment, gBExperimentResult);
    }

    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof GBFeatureResult)) {
            return false;
        }
        GBFeatureResult gBFeatureResult = (GBFeatureResult) obj;
        return Intrinsics.b(this.gbValue, gBFeatureResult.gbValue) && this.on == gBFeatureResult.on && this.off == gBFeatureResult.off && this.source == gBFeatureResult.source && Intrinsics.b(this.experiment, gBFeatureResult.experiment) && Intrinsics.b(this.experimentResult, gBFeatureResult.experimentResult);
    }

    public final GBExperiment getExperiment() {
        return this.experiment;
    }

    public final GBExperimentResult getExperimentResult() {
        return this.experimentResult;
    }

    public final GBValue getGbValue() {
        return this.gbValue;
    }

    public final boolean getOff() {
        return this.off;
    }

    public final boolean getOn() {
        return this.on;
    }

    @NotNull
    public final GBFeatureSource getSource() {
        return this.source;
    }

    public int hashCode() {
        GBValue gBValue = this.gbValue;
        int iHashCode = (this.source.hashCode() + d0.g(d0.g((gBValue == null ? 0 : gBValue.hashCode()) * 31, 31, this.on), 31, this.off)) * 31;
        GBExperiment gBExperiment = this.experiment;
        int iHashCode2 = (iHashCode + (gBExperiment == null ? 0 : gBExperiment.hashCode())) * 31;
        GBExperimentResult gBExperimentResult = this.experimentResult;
        return iHashCode2 + (gBExperimentResult != null ? gBExperimentResult.hashCode() : 0);
    }

    @NotNull
    public String toString() {
        return "GBFeatureResult(gbValue=" + this.gbValue + ", on=" + this.on + ", off=" + this.off + ", source=" + this.source + ", experiment=" + this.experiment + ", experimentResult=" + this.experimentResult + ')';
    }

    /* JADX WARN: Illegal instructions before constructor call */
    public /* synthetic */ GBFeatureResult(GBValue gBValue, boolean z, boolean z2, GBFeatureSource gBFeatureSource, GBExperiment gBExperiment, GBExperimentResult gBExperimentResult, int i, DefaultConstructorMarker defaultConstructorMarker) {
        boolean z3 = (i & 2) != 0 ? false : z;
        this(gBValue, z3, (i & 4) != 0 ? !z3 : z2, gBFeatureSource, (i & 16) != 0 ? null : gBExperiment, (i & 32) != 0 ? null : gBExperimentResult);
    }
}
