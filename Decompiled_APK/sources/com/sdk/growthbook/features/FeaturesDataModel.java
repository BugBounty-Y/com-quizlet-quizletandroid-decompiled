package com.sdk.growthbook.features;

import androidx.compose.animation.d0;
import com.sdk.growthbook.model.GBFeature;
import java.util.Map;
import kotlin.Metadata;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.serialization.json.v;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public final class FeaturesDataModel {
    private final String encryptedFeatures;
    private final String encryptedSavedGroups;
    private final Map<String, GBFeature> features;
    private final v savedGroups;

    public FeaturesDataModel() {
        this(null, null, null, null, 15, null);
    }

    /* JADX WARN: Multi-variable type inference failed */
    public static /* synthetic */ FeaturesDataModel copy$default(FeaturesDataModel featuresDataModel, Map map, String str, v vVar, String str2, int i, Object obj) {
        if ((i & 1) != 0) {
            map = featuresDataModel.features;
        }
        if ((i & 2) != 0) {
            str = featuresDataModel.encryptedFeatures;
        }
        if ((i & 4) != 0) {
            vVar = featuresDataModel.savedGroups;
        }
        if ((i & 8) != 0) {
            str2 = featuresDataModel.encryptedSavedGroups;
        }
        return featuresDataModel.copy(map, str, vVar, str2);
    }

    public final Map<String, GBFeature> component1() {
        return this.features;
    }

    public final String component2() {
        return this.encryptedFeatures;
    }

    public final v component3() {
        return this.savedGroups;
    }

    public final String component4() {
        return this.encryptedSavedGroups;
    }

    @NotNull
    public final FeaturesDataModel copy(Map<String, GBFeature> map, String str, v vVar, String str2) {
        return new FeaturesDataModel(map, str, vVar, str2);
    }

    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof FeaturesDataModel)) {
            return false;
        }
        FeaturesDataModel featuresDataModel = (FeaturesDataModel) obj;
        return Intrinsics.b(this.features, featuresDataModel.features) && Intrinsics.b(this.encryptedFeatures, featuresDataModel.encryptedFeatures) && Intrinsics.b(this.savedGroups, featuresDataModel.savedGroups) && Intrinsics.b(this.encryptedSavedGroups, featuresDataModel.encryptedSavedGroups);
    }

    public final String getEncryptedFeatures() {
        return this.encryptedFeatures;
    }

    public final String getEncryptedSavedGroups() {
        return this.encryptedSavedGroups;
    }

    public final Map<String, GBFeature> getFeatures() {
        return this.features;
    }

    public final v getSavedGroups() {
        return this.savedGroups;
    }

    public int hashCode() {
        Map<String, GBFeature> map = this.features;
        int iHashCode = (map == null ? 0 : map.hashCode()) * 31;
        String str = this.encryptedFeatures;
        int iHashCode2 = (iHashCode + (str == null ? 0 : str.hashCode())) * 31;
        v vVar = this.savedGroups;
        int iHashCode3 = (iHashCode2 + (vVar == null ? 0 : vVar.a.hashCode())) * 31;
        String str2 = this.encryptedSavedGroups;
        return iHashCode3 + (str2 != null ? str2.hashCode() : 0);
    }

    @NotNull
    public String toString() {
        StringBuilder sb = new StringBuilder("FeaturesDataModel(features=");
        sb.append(this.features);
        sb.append(", encryptedFeatures=");
        sb.append(this.encryptedFeatures);
        sb.append(", savedGroups=");
        sb.append(this.savedGroups);
        sb.append(", encryptedSavedGroups=");
        return d0.r(sb, this.encryptedSavedGroups, ')');
    }

    public FeaturesDataModel(Map<String, GBFeature> map, String str, v vVar, String str2) {
        this.features = map;
        this.encryptedFeatures = str;
        this.savedGroups = vVar;
        this.encryptedSavedGroups = str2;
    }

    public /* synthetic */ FeaturesDataModel(Map map, String str, v vVar, String str2, int i, DefaultConstructorMarker defaultConstructorMarker) {
        this((i & 1) != 0 ? null : map, (i & 2) != 0 ? null : str, (i & 4) != 0 ? null : vVar, (i & 8) != 0 ? null : str2);
    }
}
