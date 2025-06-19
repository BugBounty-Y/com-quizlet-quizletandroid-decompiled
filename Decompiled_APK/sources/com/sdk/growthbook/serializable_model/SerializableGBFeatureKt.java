package com.sdk.growthbook.serializable_model;

import com.sdk.growthbook.model.GBFeature;
import com.sdk.growthbook.model.GBValue;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import kotlin.Metadata;
import kotlin.collections.C;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.serialization.json.k;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public final class SerializableGBFeatureKt {
    @NotNull
    public static final GBFeature gbDeserialize(@NotNull SerializableGBFeature serializableGBFeature) {
        Intrinsics.checkNotNullParameter(serializableGBFeature, "<this>");
        k defaultValue = serializableGBFeature.getDefaultValue();
        ArrayList arrayList = null;
        GBValue gBValueFrom$GrowthBook_release = defaultValue != null ? GBValue.Companion.from$GrowthBook_release(defaultValue) : null;
        List<SerializableGBFeatureRule> rules = serializableGBFeature.getRules();
        if (rules != null) {
            arrayList = new ArrayList(C.q(rules, 10));
            Iterator<T> it2 = rules.iterator();
            while (it2.hasNext()) {
                arrayList.add(SerializableGBFeatureRuleKt.gbDeserialize((SerializableGBFeatureRule) it2.next()));
            }
        }
        return new GBFeature(gBValueFrom$GrowthBook_release, arrayList);
    }
}
