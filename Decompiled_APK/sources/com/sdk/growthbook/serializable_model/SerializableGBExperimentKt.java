package com.sdk.growthbook.serializable_model;

import com.sdk.growthbook.model.GBExperiment;
import com.sdk.growthbook.model.GBValue;
import com.sdk.growthbook.utils.GBFilter;
import com.sdk.growthbook.utils.GBParentConditionInterface;
import com.sdk.growthbook.utils.GBVariationMeta;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import kotlin.Metadata;
import kotlin.Pair;
import kotlin.collections.C;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.serialization.json.d;
import kotlinx.serialization.json.k;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public final class SerializableGBExperimentKt {
    @NotNull
    public static final GBExperiment gbDeserialize(@NotNull SerializableGBExperiment serializableGBExperiment) {
        Intrinsics.checkNotNullParameter(serializableGBExperiment, "<this>");
        String key = serializableGBExperiment.getKey();
        String seed = serializableGBExperiment.getSeed();
        ArrayList<GBVariationMeta> meta = serializableGBExperiment.getMeta();
        String name = serializableGBExperiment.getName();
        Integer force = serializableGBExperiment.getForce();
        String phase = serializableGBExperiment.getPhase();
        Boolean active = serializableGBExperiment.getActive();
        List<Pair<Float, Float>> ranges = serializableGBExperiment.getRanges();
        List<Float> weights = serializableGBExperiment.getWeights();
        ArrayList<GBFilter> filters = serializableGBExperiment.getFilters();
        Float coverage = serializableGBExperiment.getCoverage();
        d namespace = serializableGBExperiment.getNamespace();
        k condition = serializableGBExperiment.getCondition();
        Integer hashVersion = serializableGBExperiment.getHashVersion();
        Integer bucketVersion = serializableGBExperiment.getBucketVersion();
        String hashAttribute = serializableGBExperiment.getHashAttribute();
        Integer minBucketVersion = serializableGBExperiment.getMinBucketVersion();
        ArrayList<GBParentConditionInterface> parentConditions = serializableGBExperiment.getParentConditions();
        String fallBackAttribute = serializableGBExperiment.getFallBackAttribute();
        Boolean disableStickyBucketing = serializableGBExperiment.getDisableStickyBucketing();
        List<k> variations = serializableGBExperiment.getVariations();
        ArrayList arrayList = new ArrayList(C.q(variations, 10));
        for (Iterator it2 = variations.iterator(); it2.hasNext(); it2 = it2) {
            arrayList.add(GBValue.Companion.from$GrowthBook_release((k) it2.next()));
        }
        return new GBExperiment(key, arrayList, namespace, hashAttribute, weights, active, coverage, condition, parentConditions, force, hashVersion, ranges, meta, filters, seed, name, phase, fallBackAttribute, disableStickyBucketing, bucketVersion, minBucketVersion);
    }
}
