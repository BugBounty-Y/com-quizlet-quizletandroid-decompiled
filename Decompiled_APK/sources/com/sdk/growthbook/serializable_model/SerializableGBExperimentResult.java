package com.sdk.growthbook.serializable_model;

import androidx.compose.animation.d0;
import com.google.android.gms.ads.g;
import java.util.HashMap;
import kotlin.Metadata;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.serialization.KSerializer;
import kotlinx.serialization.descriptors.SerialDescriptor;
import kotlinx.serialization.encoding.b;
import kotlinx.serialization.f;
import kotlinx.serialization.internal.C;
import kotlinx.serialization.internal.C5053g;
import kotlinx.serialization.internal.l0;
import kotlinx.serialization.internal.q0;
import kotlinx.serialization.json.k;
import kotlinx.serialization.json.m;
import kotlinx.serialization.json.v;
import org.jetbrains.annotations.NotNull;

@f
@Metadata
/* loaded from: classes3.dex */
public final class SerializableGBExperimentResult {

    @NotNull
    public static final Companion Companion = new Companion(null);
    private Float bucket;
    private final String featureId;
    private final String hashAttribute;
    private final Boolean hashUsed;
    private final String hashValue;
    private final boolean inExperiment;

    @NotNull
    private final String key;
    private String name;
    private Boolean passthrough;
    private final Boolean stickyBucketUsed;

    @NotNull
    private final k value;
    private final int variationId;

    @Metadata
    public static final class Companion {
        private Companion() {
        }

        @NotNull
        public final KSerializer serializer() {
            return SerializableGBExperimentResult$$serializer.INSTANCE;
        }

        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }
    }

    public SerializableGBExperimentResult() {
        this(false, 0, (k) null, (String) null, (String) null, (String) null, (String) null, (Float) null, (Boolean) null, (Boolean) null, (String) null, (Boolean) null, 4095, (DefaultConstructorMarker) null);
    }

    public static /* synthetic */ SerializableGBExperimentResult copy$default(SerializableGBExperimentResult serializableGBExperimentResult, boolean z, int i, k kVar, String str, String str2, String str3, String str4, Float f, Boolean bool, Boolean bool2, String str5, Boolean bool3, int i2, Object obj) {
        if ((i2 & 1) != 0) {
            z = serializableGBExperimentResult.inExperiment;
        }
        if ((i2 & 2) != 0) {
            i = serializableGBExperimentResult.variationId;
        }
        if ((i2 & 4) != 0) {
            kVar = serializableGBExperimentResult.value;
        }
        if ((i2 & 8) != 0) {
            str = serializableGBExperimentResult.hashAttribute;
        }
        if ((i2 & 16) != 0) {
            str2 = serializableGBExperimentResult.hashValue;
        }
        if ((i2 & 32) != 0) {
            str3 = serializableGBExperimentResult.key;
        }
        if ((i2 & 64) != 0) {
            str4 = serializableGBExperimentResult.name;
        }
        if ((i2 & 128) != 0) {
            f = serializableGBExperimentResult.bucket;
        }
        if ((i2 & 256) != 0) {
            bool = serializableGBExperimentResult.passthrough;
        }
        if ((i2 & g.MAX_CONTENT_URL_LENGTH) != 0) {
            bool2 = serializableGBExperimentResult.hashUsed;
        }
        if ((i2 & 1024) != 0) {
            str5 = serializableGBExperimentResult.featureId;
        }
        if ((i2 & 2048) != 0) {
            bool3 = serializableGBExperimentResult.stickyBucketUsed;
        }
        String str6 = str5;
        Boolean bool4 = bool3;
        Boolean bool5 = bool;
        Boolean bool6 = bool2;
        String str7 = str4;
        Float f2 = f;
        String str8 = str2;
        String str9 = str3;
        return serializableGBExperimentResult.copy(z, i, kVar, str, str8, str9, str7, f2, bool5, bool6, str6, bool4);
    }

    public static final /* synthetic */ void write$Self$GrowthBook_release(SerializableGBExperimentResult serializableGBExperimentResult, b bVar, SerialDescriptor serialDescriptor) {
        if (bVar.D(serialDescriptor) || serializableGBExperimentResult.inExperiment) {
            bVar.p(serialDescriptor, 0, serializableGBExperimentResult.inExperiment);
        }
        if (bVar.D(serialDescriptor) || serializableGBExperimentResult.variationId != 0) {
            bVar.l(1, serializableGBExperimentResult.variationId, serialDescriptor);
        }
        if (bVar.D(serialDescriptor) || !Intrinsics.b(serializableGBExperimentResult.value, new v(new HashMap()))) {
            bVar.i(serialDescriptor, 2, m.a, serializableGBExperimentResult.value);
        }
        if (bVar.D(serialDescriptor) || serializableGBExperimentResult.hashAttribute != null) {
            bVar.s(serialDescriptor, 3, q0.a, serializableGBExperimentResult.hashAttribute);
        }
        if (bVar.D(serialDescriptor) || serializableGBExperimentResult.hashValue != null) {
            bVar.s(serialDescriptor, 4, q0.a, serializableGBExperimentResult.hashValue);
        }
        if (bVar.D(serialDescriptor) || !Intrinsics.b(serializableGBExperimentResult.key, "")) {
            bVar.r(serialDescriptor, 5, serializableGBExperimentResult.key);
        }
        if (bVar.D(serialDescriptor) || serializableGBExperimentResult.name != null) {
            bVar.s(serialDescriptor, 6, q0.a, serializableGBExperimentResult.name);
        }
        if (bVar.D(serialDescriptor) || serializableGBExperimentResult.bucket != null) {
            bVar.s(serialDescriptor, 7, C.a, serializableGBExperimentResult.bucket);
        }
        if (bVar.D(serialDescriptor) || serializableGBExperimentResult.passthrough != null) {
            bVar.s(serialDescriptor, 8, C5053g.a, serializableGBExperimentResult.passthrough);
        }
        if (bVar.D(serialDescriptor) || serializableGBExperimentResult.hashUsed != null) {
            bVar.s(serialDescriptor, 9, C5053g.a, serializableGBExperimentResult.hashUsed);
        }
        if (bVar.D(serialDescriptor) || serializableGBExperimentResult.featureId != null) {
            bVar.s(serialDescriptor, 10, q0.a, serializableGBExperimentResult.featureId);
        }
        if (!bVar.D(serialDescriptor) && serializableGBExperimentResult.stickyBucketUsed == null) {
            return;
        }
        bVar.s(serialDescriptor, 11, C5053g.a, serializableGBExperimentResult.stickyBucketUsed);
    }

    public final boolean component1() {
        return this.inExperiment;
    }

    public final Boolean component10() {
        return this.hashUsed;
    }

    public final String component11() {
        return this.featureId;
    }

    public final Boolean component12() {
        return this.stickyBucketUsed;
    }

    public final int component2() {
        return this.variationId;
    }

    @NotNull
    public final k component3() {
        return this.value;
    }

    public final String component4() {
        return this.hashAttribute;
    }

    public final String component5() {
        return this.hashValue;
    }

    @NotNull
    public final String component6() {
        return this.key;
    }

    public final String component7() {
        return this.name;
    }

    public final Float component8() {
        return this.bucket;
    }

    public final Boolean component9() {
        return this.passthrough;
    }

    @NotNull
    public final SerializableGBExperimentResult copy(boolean z, int i, @NotNull k value, String str, String str2, @NotNull String key, String str3, Float f, Boolean bool, Boolean bool2, String str4, Boolean bool3) {
        Intrinsics.checkNotNullParameter(value, "value");
        Intrinsics.checkNotNullParameter(key, "key");
        return new SerializableGBExperimentResult(z, i, value, str, str2, key, str3, f, bool, bool2, str4, bool3);
    }

    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof SerializableGBExperimentResult)) {
            return false;
        }
        SerializableGBExperimentResult serializableGBExperimentResult = (SerializableGBExperimentResult) obj;
        return this.inExperiment == serializableGBExperimentResult.inExperiment && this.variationId == serializableGBExperimentResult.variationId && Intrinsics.b(this.value, serializableGBExperimentResult.value) && Intrinsics.b(this.hashAttribute, serializableGBExperimentResult.hashAttribute) && Intrinsics.b(this.hashValue, serializableGBExperimentResult.hashValue) && Intrinsics.b(this.key, serializableGBExperimentResult.key) && Intrinsics.b(this.name, serializableGBExperimentResult.name) && Intrinsics.b(this.bucket, serializableGBExperimentResult.bucket) && Intrinsics.b(this.passthrough, serializableGBExperimentResult.passthrough) && Intrinsics.b(this.hashUsed, serializableGBExperimentResult.hashUsed) && Intrinsics.b(this.featureId, serializableGBExperimentResult.featureId) && Intrinsics.b(this.stickyBucketUsed, serializableGBExperimentResult.stickyBucketUsed);
    }

    public final Float getBucket() {
        return this.bucket;
    }

    public final String getFeatureId() {
        return this.featureId;
    }

    public final String getHashAttribute() {
        return this.hashAttribute;
    }

    public final Boolean getHashUsed() {
        return this.hashUsed;
    }

    public final String getHashValue() {
        return this.hashValue;
    }

    public final boolean getInExperiment() {
        return this.inExperiment;
    }

    @NotNull
    public final String getKey() {
        return this.key;
    }

    public final String getName() {
        return this.name;
    }

    public final Boolean getPassthrough() {
        return this.passthrough;
    }

    public final Boolean getStickyBucketUsed() {
        return this.stickyBucketUsed;
    }

    @NotNull
    public final k getValue() {
        return this.value;
    }

    public final int getVariationId() {
        return this.variationId;
    }

    public int hashCode() {
        int iHashCode = (this.value.hashCode() + d0.b(this.variationId, Boolean.hashCode(this.inExperiment) * 31, 31)) * 31;
        String str = this.hashAttribute;
        int iHashCode2 = (iHashCode + (str == null ? 0 : str.hashCode())) * 31;
        String str2 = this.hashValue;
        int iE = d0.e((iHashCode2 + (str2 == null ? 0 : str2.hashCode())) * 31, 31, this.key);
        String str3 = this.name;
        int iHashCode3 = (iE + (str3 == null ? 0 : str3.hashCode())) * 31;
        Float f = this.bucket;
        int iHashCode4 = (iHashCode3 + (f == null ? 0 : f.hashCode())) * 31;
        Boolean bool = this.passthrough;
        int iHashCode5 = (iHashCode4 + (bool == null ? 0 : bool.hashCode())) * 31;
        Boolean bool2 = this.hashUsed;
        int iHashCode6 = (iHashCode5 + (bool2 == null ? 0 : bool2.hashCode())) * 31;
        String str4 = this.featureId;
        int iHashCode7 = (iHashCode6 + (str4 == null ? 0 : str4.hashCode())) * 31;
        Boolean bool3 = this.stickyBucketUsed;
        return iHashCode7 + (bool3 != null ? bool3.hashCode() : 0);
    }

    public final void setBucket(Float f) {
        this.bucket = f;
    }

    public final void setName(String str) {
        this.name = str;
    }

    public final void setPassthrough(Boolean bool) {
        this.passthrough = bool;
    }

    @NotNull
    public String toString() {
        return "SerializableGBExperimentResult(inExperiment=" + this.inExperiment + ", variationId=" + this.variationId + ", value=" + this.value + ", hashAttribute=" + this.hashAttribute + ", hashValue=" + this.hashValue + ", key=" + this.key + ", name=" + this.name + ", bucket=" + this.bucket + ", passthrough=" + this.passthrough + ", hashUsed=" + this.hashUsed + ", featureId=" + this.featureId + ", stickyBucketUsed=" + this.stickyBucketUsed + ')';
    }

    public /* synthetic */ SerializableGBExperimentResult(int i, boolean z, int i2, k kVar, String str, String str2, String str3, String str4, Float f, Boolean bool, Boolean bool2, String str5, Boolean bool3, l0 l0Var) {
        if ((i & 1) == 0) {
            this.inExperiment = false;
        } else {
            this.inExperiment = z;
        }
        if ((i & 2) == 0) {
            this.variationId = 0;
        } else {
            this.variationId = i2;
        }
        if ((i & 4) == 0) {
            this.value = new v(new HashMap());
        } else {
            this.value = kVar;
        }
        if ((i & 8) == 0) {
            this.hashAttribute = null;
        } else {
            this.hashAttribute = str;
        }
        if ((i & 16) == 0) {
            this.hashValue = null;
        } else {
            this.hashValue = str2;
        }
        if ((i & 32) == 0) {
            this.key = "";
        } else {
            this.key = str3;
        }
        if ((i & 64) == 0) {
            this.name = null;
        } else {
            this.name = str4;
        }
        if ((i & 128) == 0) {
            this.bucket = null;
        } else {
            this.bucket = f;
        }
        if ((i & 256) == 0) {
            this.passthrough = null;
        } else {
            this.passthrough = bool;
        }
        if ((i & g.MAX_CONTENT_URL_LENGTH) == 0) {
            this.hashUsed = null;
        } else {
            this.hashUsed = bool2;
        }
        if ((i & 1024) == 0) {
            this.featureId = null;
        } else {
            this.featureId = str5;
        }
        if ((i & 2048) == 0) {
            this.stickyBucketUsed = null;
        } else {
            this.stickyBucketUsed = bool3;
        }
    }

    public SerializableGBExperimentResult(boolean z, int i, @NotNull k value, String str, String str2, @NotNull String key, String str3, Float f, Boolean bool, Boolean bool2, String str4, Boolean bool3) {
        Intrinsics.checkNotNullParameter(value, "value");
        Intrinsics.checkNotNullParameter(key, "key");
        this.inExperiment = z;
        this.variationId = i;
        this.value = value;
        this.hashAttribute = str;
        this.hashValue = str2;
        this.key = key;
        this.name = str3;
        this.bucket = f;
        this.passthrough = bool;
        this.hashUsed = bool2;
        this.featureId = str4;
        this.stickyBucketUsed = bool3;
    }

    public /* synthetic */ SerializableGBExperimentResult(boolean z, int i, k kVar, String str, String str2, String str3, String str4, Float f, Boolean bool, Boolean bool2, String str5, Boolean bool3, int i2, DefaultConstructorMarker defaultConstructorMarker) {
        this((i2 & 1) != 0 ? false : z, (i2 & 2) != 0 ? 0 : i, (i2 & 4) != 0 ? new v(new HashMap()) : kVar, (i2 & 8) != 0 ? null : str, (i2 & 16) != 0 ? null : str2, (i2 & 32) != 0 ? "" : str3, (i2 & 64) != 0 ? null : str4, (i2 & 128) != 0 ? null : f, (i2 & 256) != 0 ? null : bool, (i2 & g.MAX_CONTENT_URL_LENGTH) != 0 ? null : bool2, (i2 & 1024) != 0 ? null : str5, (i2 & 2048) != 0 ? null : bool3);
    }
}
