package com.sdk.growthbook.model;

import com.sdk.growthbook.serializable_model.SerializableGBFeature;
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
public final class GBFeatureKt {
    @NotNull
    public static final SerializableGBFeature gbSerialize(@NotNull GBFeature gBFeature) {
        Intrinsics.checkNotNullParameter(gBFeature, "<this>");
        GBValue defaultValue = gBFeature.getDefaultValue();
        ArrayList arrayList = null;
        k kVarGbSerialize$GrowthBook_release = defaultValue != null ? defaultValue.gbSerialize$GrowthBook_release() : null;
        List<GBFeatureRule> rules = gBFeature.getRules();
        if (rules != null) {
            arrayList = new ArrayList(C.q(rules, 10));
            Iterator<T> it2 = rules.iterator();
            while (it2.hasNext()) {
                arrayList.add(((GBFeatureRule) it2.next()).gbSerialize$GrowthBook_release());
            }
        }
        return new SerializableGBFeature(kVarGbSerialize$GrowthBook_release, arrayList);
    }
}
