package com.sdk.growthbook.serializable_model;

import java.util.List;
import kotlin.Metadata;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.serialization.KSerializer;
import kotlinx.serialization.descriptors.SerialDescriptor;
import kotlinx.serialization.encoding.b;
import kotlinx.serialization.f;
import kotlinx.serialization.internal.C5048d;
import kotlinx.serialization.internal.l0;
import kotlinx.serialization.json.k;
import kotlinx.serialization.json.m;
import org.jetbrains.annotations.NotNull;

@f
@Metadata
/* loaded from: classes3.dex */
public final class SerializableGBFeature {
    private final k defaultValue;
    private final List<SerializableGBFeatureRule> rules;

    @NotNull
    public static final Companion Companion = new Companion(null);

    @NotNull
    private static final KSerializer[] $childSerializers = {null, new C5048d(SerializableGBFeatureRule$$serializer.INSTANCE, 0)};

    @Metadata
    public static final class Companion {
        private Companion() {
        }

        @NotNull
        public final KSerializer serializer() {
            return SerializableGBFeature$$serializer.INSTANCE;
        }

        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }
    }

    /* JADX WARN: Multi-variable type inference failed */
    public SerializableGBFeature() {
        this((k) null, (List) (0 == true ? 1 : 0), 3, (DefaultConstructorMarker) (0 == true ? 1 : 0));
    }

    /* JADX WARN: Multi-variable type inference failed */
    public static /* synthetic */ SerializableGBFeature copy$default(SerializableGBFeature serializableGBFeature, k kVar, List list, int i, Object obj) {
        if ((i & 1) != 0) {
            kVar = serializableGBFeature.defaultValue;
        }
        if ((i & 2) != 0) {
            list = serializableGBFeature.rules;
        }
        return serializableGBFeature.copy(kVar, list);
    }

    public static final /* synthetic */ void write$Self$GrowthBook_release(SerializableGBFeature serializableGBFeature, b bVar, SerialDescriptor serialDescriptor) {
        KSerializer[] kSerializerArr = $childSerializers;
        if (bVar.D(serialDescriptor) || serializableGBFeature.defaultValue != null) {
            bVar.s(serialDescriptor, 0, m.a, serializableGBFeature.defaultValue);
        }
        if (!bVar.D(serialDescriptor) && serializableGBFeature.rules == null) {
            return;
        }
        bVar.s(serialDescriptor, 1, kSerializerArr[1], serializableGBFeature.rules);
    }

    public final k component1() {
        return this.defaultValue;
    }

    public final List<SerializableGBFeatureRule> component2() {
        return this.rules;
    }

    @NotNull
    public final SerializableGBFeature copy(k kVar, List<SerializableGBFeatureRule> list) {
        return new SerializableGBFeature(kVar, list);
    }

    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof SerializableGBFeature)) {
            return false;
        }
        SerializableGBFeature serializableGBFeature = (SerializableGBFeature) obj;
        return Intrinsics.b(this.defaultValue, serializableGBFeature.defaultValue) && Intrinsics.b(this.rules, serializableGBFeature.rules);
    }

    public final k getDefaultValue() {
        return this.defaultValue;
    }

    public final List<SerializableGBFeatureRule> getRules() {
        return this.rules;
    }

    public int hashCode() {
        k kVar = this.defaultValue;
        int iHashCode = (kVar == null ? 0 : kVar.hashCode()) * 31;
        List<SerializableGBFeatureRule> list = this.rules;
        return iHashCode + (list != null ? list.hashCode() : 0);
    }

    @NotNull
    public String toString() {
        return "SerializableGBFeature(defaultValue=" + this.defaultValue + ", rules=" + this.rules + ')';
    }

    public /* synthetic */ SerializableGBFeature(int i, k kVar, List list, l0 l0Var) {
        if ((i & 1) == 0) {
            this.defaultValue = null;
        } else {
            this.defaultValue = kVar;
        }
        if ((i & 2) == 0) {
            this.rules = null;
        } else {
            this.rules = list;
        }
    }

    public SerializableGBFeature(k kVar, List<SerializableGBFeatureRule> list) {
        this.defaultValue = kVar;
        this.rules = list;
    }

    public /* synthetic */ SerializableGBFeature(k kVar, List list, int i, DefaultConstructorMarker defaultConstructorMarker) {
        this((i & 1) != 0 ? null : kVar, (i & 2) != 0 ? null : list);
    }
}
