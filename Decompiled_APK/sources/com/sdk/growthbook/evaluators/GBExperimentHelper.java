package com.sdk.growthbook.evaluators;

import com.sdk.growthbook.model.GBExperiment;
import com.sdk.growthbook.model.GBExperimentResult;
import java.util.LinkedHashSet;
import java.util.Set;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public final class GBExperimentHelper {

    @NotNull
    private Set<String> trackedExperiments = new LinkedHashSet();

    public final boolean isTracked(@NotNull GBExperiment experiment, GBExperimentResult gBExperimentResult) {
        String hashAttribute;
        String hashValue;
        Intrinsics.checkNotNullParameter(experiment, "experiment");
        String key = experiment.getKey();
        StringBuilder sb = new StringBuilder();
        String str = "";
        if (gBExperimentResult == null || (hashAttribute = gBExperimentResult.getHashAttribute()) == null) {
            hashAttribute = "";
        }
        sb.append(hashAttribute);
        if (gBExperimentResult != null && (hashValue = gBExperimentResult.getHashValue()) != null) {
            str = hashValue;
        }
        sb.append(str);
        sb.append(key);
        sb.append(gBExperimentResult != null ? Integer.valueOf(gBExperimentResult.getVariationId()) : null);
        String string = sb.toString();
        if (this.trackedExperiments.contains(string)) {
            return true;
        }
        this.trackedExperiments.add(string);
        return false;
    }
}
