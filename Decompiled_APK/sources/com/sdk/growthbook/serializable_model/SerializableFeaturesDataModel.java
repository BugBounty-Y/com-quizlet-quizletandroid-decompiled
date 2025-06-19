package com.sdk.growthbook.serializable_model;

import androidx.compose.animation.d0;
import java.util.Map;
import kotlin.Metadata;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.serialization.KSerializer;
import kotlinx.serialization.descriptors.SerialDescriptor;
import kotlinx.serialization.encoding.b;
import kotlinx.serialization.f;
import kotlinx.serialization.internal.F;
import kotlinx.serialization.internal.l0;
import kotlinx.serialization.internal.q0;
import kotlinx.serialization.json.v;
import kotlinx.serialization.json.x;
import org.jetbrains.annotations.NotNull;

@f
@Metadata
/* loaded from: classes3.dex */
public final class SerializableFeaturesDataModel {
    private final String encryptedFeatures;
    private final String encryptedSavedGroups;
    private final Map<String, SerializableGBFeature> features;
    private final v savedGroups;

    @NotNull
    public static final Companion Companion = new Companion(null);

    @NotNull
    private static final KSerializer[] $childSerializers = {new F(q0.a, SerializableGBFeature$$serializer.INSTANCE, 1), null, null, null};

    @Metadata
    public static final class Companion {
        private Companion() {
        }

        @NotNull
        public final KSerializer serializer() {
            return SerializableFeaturesDataModel$$serializer.INSTANCE;
        }

        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }
    }

    public SerializableFeaturesDataModel() {
        this((Map) null, (String) null, (v) null, (String) null, 15, (DefaultConstructorMarker) null);
    }

    /* JADX WARN: Multi-variable type inference failed */
    public static /* synthetic */ SerializableFeaturesDataModel copy$default(SerializableFeaturesDataModel serializableFeaturesDataModel, Map map, String str, v vVar, String str2, int i, Object obj) {
        if ((i & 1) != 0) {
            map = serializableFeaturesDataModel.features;
        }
        if ((i & 2) != 0) {
            str = serializableFeaturesDataModel.encryptedFeatures;
        }
        if ((i & 4) != 0) {
            vVar = serializableFeaturesDataModel.savedGroups;
        }
        if ((i & 8) != 0) {
            str2 = serializableFeaturesDataModel.encryptedSavedGroups;
        }
        return serializableFeaturesDataModel.copy(map, str, vVar, str2);
    }

    public static final /* synthetic */ void write$Self$GrowthBook_release(SerializableFeaturesDataModel serializableFeaturesDataModel, b bVar, SerialDescriptor serialDescriptor) {
        KSerializer[] kSerializerArr = $childSerializers;
        if (bVar.D(serialDescriptor) || serializableFeaturesDataModel.features != null) {
            bVar.s(serialDescriptor, 0, kSerializerArr[0], serializableFeaturesDataModel.features);
        }
        if (bVar.D(serialDescriptor) || serializableFeaturesDataModel.encryptedFeatures != null) {
            bVar.s(serialDescriptor, 1, q0.a, serializableFeaturesDataModel.encryptedFeatures);
        }
        if (bVar.D(serialDescriptor) || serializableFeaturesDataModel.savedGroups != null) {
            bVar.s(serialDescriptor, 2, x.a, serializableFeaturesDataModel.savedGroups);
        }
        if (!bVar.D(serialDescriptor) && serializableFeaturesDataModel.encryptedSavedGroups == null) {
            return;
        }
        bVar.s(serialDescriptor, 3, q0.a, serializableFeaturesDataModel.encryptedSavedGroups);
    }

    public final Map<String, SerializableGBFeature> component1() {
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
    public final SerializableFeaturesDataModel copy(Map<String, SerializableGBFeature> map, String str, v vVar, String str2) {
        return new SerializableFeaturesDataModel(map, str, vVar, str2);
    }

    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof SerializableFeaturesDataModel)) {
            return false;
        }
        SerializableFeaturesDataModel serializableFeaturesDataModel = (SerializableFeaturesDataModel) obj;
        return Intrinsics.b(this.features, serializableFeaturesDataModel.features) && Intrinsics.b(this.encryptedFeatures, serializableFeaturesDataModel.encryptedFeatures) && Intrinsics.b(this.savedGroups, serializableFeaturesDataModel.savedGroups) && Intrinsics.b(this.encryptedSavedGroups, serializableFeaturesDataModel.encryptedSavedGroups);
    }

    public final String getEncryptedFeatures() {
        return this.encryptedFeatures;
    }

    public final String getEncryptedSavedGroups() {
        return this.encryptedSavedGroups;
    }

    public final Map<String, SerializableGBFeature> getFeatures() {
        return this.features;
    }

    public final v getSavedGroups() {
        return this.savedGroups;
    }

    public int hashCode() {
        Map<String, SerializableGBFeature> map = this.features;
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
        StringBuilder sb = new StringBuilder("SerializableFeaturesDataModel(features=");
        sb.append(this.features);
        sb.append(", encryptedFeatures=");
        sb.append(this.encryptedFeatures);
        sb.append(", savedGroups=");
        sb.append(this.savedGroups);
        sb.append(", encryptedSavedGroups=");
        return d0.r(sb, this.encryptedSavedGroups, ')');
    }

    public /* synthetic */ SerializableFeaturesDataModel(int i, Map map, String str, v vVar, String str2, l0 l0Var) {
        if ((i & 1) == 0) {
            this.features = null;
        } else {
            this.features = map;
        }
        if ((i & 2) == 0) {
            this.encryptedFeatures = null;
        } else {
            this.encryptedFeatures = str;
        }
        if ((i & 4) == 0) {
            this.savedGroups = null;
        } else {
            this.savedGroups = vVar;
        }
        if ((i & 8) == 0) {
            this.encryptedSavedGroups = null;
        } else {
            this.encryptedSavedGroups = str2;
        }
    }

    public SerializableFeaturesDataModel(Map<String, SerializableGBFeature> map, String str, v vVar, String str2) {
        this.features = map;
        this.encryptedFeatures = str;
        this.savedGroups = vVar;
        this.encryptedSavedGroups = str2;
    }

    public /* synthetic */ SerializableFeaturesDataModel(Map map, String str, v vVar, String str2, int i, DefaultConstructorMarker defaultConstructorMarker) {
        this((i & 1) != 0 ? null : map, (i & 2) != 0 ? null : str, (i & 4) != 0 ? null : vVar, (i & 8) != 0 ? null : str2);
    }
}
