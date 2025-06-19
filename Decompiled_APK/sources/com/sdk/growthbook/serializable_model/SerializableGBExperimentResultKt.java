package com.sdk.growthbook.serializable_model;

import com.sdk.growthbook.model.GBExperimentResult;
import com.sdk.growthbook.model.GBValue;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public final class SerializableGBExperimentResultKt {
    @NotNull
    public static final GBExperimentResult gbDeserialize(@NotNull SerializableGBExperimentResult serializableGBExperimentResult) {
        Intrinsics.checkNotNullParameter(serializableGBExperimentResult, "<this>");
        String key = serializableGBExperimentResult.getKey();
        String name = serializableGBExperimentResult.getName();
        Float bucket = serializableGBExperimentResult.getBucket();
        Boolean hashUsed = serializableGBExperimentResult.getHashUsed();
        String hashValue = serializableGBExperimentResult.getHashValue();
        String featureId = serializableGBExperimentResult.getFeatureId();
        int variationId = serializableGBExperimentResult.getVariationId();
        Boolean passthrough = serializableGBExperimentResult.getPassthrough();
        return new GBExperimentResult(serializableGBExperimentResult.getInExperiment(), variationId, GBValue.Companion.from$GrowthBook_release(serializableGBExperimentResult.getValue()), serializableGBExperimentResult.getHashAttribute(), hashValue, key, name, bucket, passthrough, hashUsed, featureId, serializableGBExperimentResult.getStickyBucketUsed());
    }
}
