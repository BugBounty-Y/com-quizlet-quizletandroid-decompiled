package com.sdk.growthbook.features;

import com.sdk.growthbook.model.GBFeature;
import com.sdk.growthbook.model.GBFeatureKt;
import com.sdk.growthbook.serializable_model.SerializableFeaturesDataModel;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;
import kotlin.Metadata;
import kotlin.collections.U;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public final class FeaturesDataModelKt {
    @NotNull
    public static final SerializableFeaturesDataModel gbSerialize(@NotNull FeaturesDataModel featuresDataModel) {
        LinkedHashMap linkedHashMap;
        Intrinsics.checkNotNullParameter(featuresDataModel, "<this>");
        Map<String, GBFeature> features = featuresDataModel.getFeatures();
        if (features != null) {
            linkedHashMap = new LinkedHashMap(U.a(features.size()));
            Iterator<T> it2 = features.entrySet().iterator();
            while (it2.hasNext()) {
                Map.Entry entry = (Map.Entry) it2.next();
                linkedHashMap.put(entry.getKey(), GBFeatureKt.gbSerialize((GBFeature) entry.getValue()));
            }
        } else {
            linkedHashMap = null;
        }
        return new SerializableFeaturesDataModel(linkedHashMap, featuresDataModel.getEncryptedFeatures(), featuresDataModel.getSavedGroups(), featuresDataModel.getEncryptedSavedGroups());
    }
}
