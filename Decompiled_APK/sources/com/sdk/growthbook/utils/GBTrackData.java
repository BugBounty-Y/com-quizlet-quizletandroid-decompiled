package com.sdk.growthbook.utils;

import com.sdk.growthbook.model.GBExperiment;
import com.sdk.growthbook.model.GBExperimentResult;
import com.sdk.growthbook.serializable_model.SerializableGBTrackData;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public final class GBTrackData {

    @NotNull
    private GBExperiment experiment;

    @NotNull
    private GBExperimentResult result;

    public GBTrackData(@NotNull GBExperiment experiment, @NotNull GBExperimentResult result) {
        Intrinsics.checkNotNullParameter(experiment, "experiment");
        Intrinsics.checkNotNullParameter(result, "result");
        this.experiment = experiment;
        this.result = result;
    }

    public static /* synthetic */ GBTrackData copy$default(GBTrackData gBTrackData, GBExperiment gBExperiment, GBExperimentResult gBExperimentResult, int i, Object obj) {
        if ((i & 1) != 0) {
            gBExperiment = gBTrackData.experiment;
        }
        if ((i & 2) != 0) {
            gBExperimentResult = gBTrackData.result;
        }
        return gBTrackData.copy(gBExperiment, gBExperimentResult);
    }

    @NotNull
    public final GBExperiment component1() {
        return this.experiment;
    }

    @NotNull
    public final GBExperimentResult component2() {
        return this.result;
    }

    @NotNull
    public final GBTrackData copy(@NotNull GBExperiment experiment, @NotNull GBExperimentResult result) {
        Intrinsics.checkNotNullParameter(experiment, "experiment");
        Intrinsics.checkNotNullParameter(result, "result");
        return new GBTrackData(experiment, result);
    }

    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof GBTrackData)) {
            return false;
        }
        GBTrackData gBTrackData = (GBTrackData) obj;
        return Intrinsics.b(this.experiment, gBTrackData.experiment) && Intrinsics.b(this.result, gBTrackData.result);
    }

    @NotNull
    public final SerializableGBTrackData gbSerialize$GrowthBook_release() {
        return new SerializableGBTrackData(this.experiment.gbSerialize$GrowthBook_release(), this.result.gbSerialize$GrowthBook_release());
    }

    @NotNull
    public final GBExperiment getExperiment() {
        return this.experiment;
    }

    @NotNull
    public final GBExperimentResult getResult() {
        return this.result;
    }

    public int hashCode() {
        return this.result.hashCode() + (this.experiment.hashCode() * 31);
    }

    public final void setExperiment(@NotNull GBExperiment gBExperiment) {
        Intrinsics.checkNotNullParameter(gBExperiment, "<set-?>");
        this.experiment = gBExperiment;
    }

    public final void setResult(@NotNull GBExperimentResult gBExperimentResult) {
        Intrinsics.checkNotNullParameter(gBExperimentResult, "<set-?>");
        this.result = gBExperimentResult;
    }

    @NotNull
    public String toString() {
        return "GBTrackData(experiment=" + this.experiment + ", result=" + this.result + ')';
    }
}
