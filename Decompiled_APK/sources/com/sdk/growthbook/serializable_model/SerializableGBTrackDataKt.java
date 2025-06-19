package com.sdk.growthbook.serializable_model;

import com.sdk.growthbook.utils.GBTrackData;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public final class SerializableGBTrackDataKt {
    @NotNull
    public static final GBTrackData gbDeserialize(@NotNull SerializableGBTrackData serializableGBTrackData) {
        Intrinsics.checkNotNullParameter(serializableGBTrackData, "<this>");
        return new GBTrackData(SerializableGBExperimentKt.gbDeserialize(serializableGBTrackData.getExperiment()), SerializableGBExperimentResultKt.gbDeserialize(serializableGBTrackData.getResult()));
    }
}
