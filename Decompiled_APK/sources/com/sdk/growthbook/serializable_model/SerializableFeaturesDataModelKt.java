package com.sdk.growthbook.serializable_model;

import com.sdk.growthbook.features.FeaturesDataModel;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;
import kotlin.Metadata;
import kotlin.collections.U;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public final class SerializableFeaturesDataModelKt {
    @NotNull
    public static final FeaturesDataModel gbDeserialize(@NotNull SerializableFeaturesDataModel serializableFeaturesDataModel) {
        LinkedHashMap linkedHashMap;
        Intrinsics.checkNotNullParameter(serializableFeaturesDataModel, "<this>");
        Map<String, SerializableGBFeature> features = serializableFeaturesDataModel.getFeatures();
        if (features != null) {
            linkedHashMap = new LinkedHashMap(U.a(features.size()));
            Iterator<T> it2 = features.entrySet().iterator();
            while (it2.hasNext()) {
                Map.Entry entry = (Map.Entry) it2.next();
                linkedHashMap.put(entry.getKey(), SerializableGBFeatureKt.gbDeserialize((SerializableGBFeature) entry.getValue()));
            }
        } else {
            linkedHashMap = null;
        }
        return new FeaturesDataModel(linkedHashMap, serializableFeaturesDataModel.getEncryptedFeatures(), serializableFeaturesDataModel.getSavedGroups(), serializableFeaturesDataModel.getEncryptedSavedGroups());
    }
}
