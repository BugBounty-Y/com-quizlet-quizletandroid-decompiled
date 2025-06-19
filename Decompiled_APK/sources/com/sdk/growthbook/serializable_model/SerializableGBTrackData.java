package com.sdk.growthbook.serializable_model;

import kotlin.Metadata;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.serialization.KSerializer;
import kotlinx.serialization.descriptors.SerialDescriptor;
import kotlinx.serialization.encoding.b;
import kotlinx.serialization.f;
import kotlinx.serialization.internal.AbstractC5047c0;
import kotlinx.serialization.internal.l0;
import org.jetbrains.annotations.NotNull;

@f
@Metadata
/* loaded from: classes3.dex */
public final class SerializableGBTrackData {

    @NotNull
    public static final Companion Companion = new Companion(null);

    @NotNull
    private SerializableGBExperiment experiment;

    @NotNull
    private SerializableGBExperimentResult result;

    @Metadata
    public static final class Companion {
        private Companion() {
        }

        @NotNull
        public final KSerializer serializer() {
            return SerializableGBTrackData$$serializer.INSTANCE;
        }

        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }
    }

    public /* synthetic */ SerializableGBTrackData(int i, SerializableGBExperiment serializableGBExperiment, SerializableGBExperimentResult serializableGBExperimentResult, l0 l0Var) {
        if (3 != (i & 3)) {
            AbstractC5047c0.k(i, 3, SerializableGBTrackData$$serializer.INSTANCE.getDescriptor());
            throw null;
        }
        this.experiment = serializableGBExperiment;
        this.result = serializableGBExperimentResult;
    }

    public static /* synthetic */ SerializableGBTrackData copy$default(SerializableGBTrackData serializableGBTrackData, SerializableGBExperiment serializableGBExperiment, SerializableGBExperimentResult serializableGBExperimentResult, int i, Object obj) {
        if ((i & 1) != 0) {
            serializableGBExperiment = serializableGBTrackData.experiment;
        }
        if ((i & 2) != 0) {
            serializableGBExperimentResult = serializableGBTrackData.result;
        }
        return serializableGBTrackData.copy(serializableGBExperiment, serializableGBExperimentResult);
    }

    public static final /* synthetic */ void write$Self$GrowthBook_release(SerializableGBTrackData serializableGBTrackData, b bVar, SerialDescriptor serialDescriptor) {
        bVar.i(serialDescriptor, 0, SerializableGBExperiment$$serializer.INSTANCE, serializableGBTrackData.experiment);
        bVar.i(serialDescriptor, 1, SerializableGBExperimentResult$$serializer.INSTANCE, serializableGBTrackData.result);
    }

    @NotNull
    public final SerializableGBExperiment component1() {
        return this.experiment;
    }

    @NotNull
    public final SerializableGBExperimentResult component2() {
        return this.result;
    }

    @NotNull
    public final SerializableGBTrackData copy(@NotNull SerializableGBExperiment experiment, @NotNull SerializableGBExperimentResult result) {
        Intrinsics.checkNotNullParameter(experiment, "experiment");
        Intrinsics.checkNotNullParameter(result, "result");
        return new SerializableGBTrackData(experiment, result);
    }

    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof SerializableGBTrackData)) {
            return false;
        }
        SerializableGBTrackData serializableGBTrackData = (SerializableGBTrackData) obj;
        return Intrinsics.b(this.experiment, serializableGBTrackData.experiment) && Intrinsics.b(this.result, serializableGBTrackData.result);
    }

    @NotNull
    public final SerializableGBExperiment getExperiment() {
        return this.experiment;
    }

    @NotNull
    public final SerializableGBExperimentResult getResult() {
        return this.result;
    }

    public int hashCode() {
        return this.result.hashCode() + (this.experiment.hashCode() * 31);
    }

    public final void setExperiment(@NotNull SerializableGBExperiment serializableGBExperiment) {
        Intrinsics.checkNotNullParameter(serializableGBExperiment, "<set-?>");
        this.experiment = serializableGBExperiment;
    }

    public final void setResult(@NotNull SerializableGBExperimentResult serializableGBExperimentResult) {
        Intrinsics.checkNotNullParameter(serializableGBExperimentResult, "<set-?>");
        this.result = serializableGBExperimentResult;
    }

    @NotNull
    public String toString() {
        return "SerializableGBTrackData(experiment=" + this.experiment + ", result=" + this.result + ')';
    }

    public SerializableGBTrackData(@NotNull SerializableGBExperiment experiment, @NotNull SerializableGBExperimentResult result) {
        Intrinsics.checkNotNullParameter(experiment, "experiment");
        Intrinsics.checkNotNullParameter(result, "result");
        this.experiment = experiment;
        this.result = result;
    }
}
