package com.sdk.growthbook.model;

import androidx.compose.animation.d0;
import com.google.android.gms.ads.g;
import com.sdk.growthbook.serializable_model.SerializableGBExperimentResult;
import kotlin.Metadata;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public final class GBExperimentResult {
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
    private final GBValue value;
    private final int variationId;

    public GBExperimentResult(boolean z, int i, @NotNull GBValue value, String str, String str2, @NotNull String key, String str3, Float f, Boolean bool, Boolean bool2, String str4, Boolean bool3) {
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

    public static /* synthetic */ GBExperimentResult copy$default(GBExperimentResult gBExperimentResult, boolean z, int i, GBValue gBValue, String str, String str2, String str3, String str4, Float f, Boolean bool, Boolean bool2, String str5, Boolean bool3, int i2, Object obj) {
        if ((i2 & 1) != 0) {
            z = gBExperimentResult.inExperiment;
        }
        if ((i2 & 2) != 0) {
            i = gBExperimentResult.variationId;
        }
        if ((i2 & 4) != 0) {
            gBValue = gBExperimentResult.value;
        }
        if ((i2 & 8) != 0) {
            str = gBExperimentResult.hashAttribute;
        }
        if ((i2 & 16) != 0) {
            str2 = gBExperimentResult.hashValue;
        }
        if ((i2 & 32) != 0) {
            str3 = gBExperimentResult.key;
        }
        if ((i2 & 64) != 0) {
            str4 = gBExperimentResult.name;
        }
        if ((i2 & 128) != 0) {
            f = gBExperimentResult.bucket;
        }
        if ((i2 & 256) != 0) {
            bool = gBExperimentResult.passthrough;
        }
        if ((i2 & g.MAX_CONTENT_URL_LENGTH) != 0) {
            bool2 = gBExperimentResult.hashUsed;
        }
        if ((i2 & 1024) != 0) {
            str5 = gBExperimentResult.featureId;
        }
        if ((i2 & 2048) != 0) {
            bool3 = gBExperimentResult.stickyBucketUsed;
        }
        String str6 = str5;
        Boolean bool4 = bool3;
        Boolean bool5 = bool;
        Boolean bool6 = bool2;
        String str7 = str4;
        Float f2 = f;
        String str8 = str2;
        String str9 = str3;
        return gBExperimentResult.copy(z, i, gBValue, str, str8, str9, str7, f2, bool5, bool6, str6, bool4);
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
    public final GBValue component3() {
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
    public final GBExperimentResult copy(boolean z, int i, @NotNull GBValue value, String str, String str2, @NotNull String key, String str3, Float f, Boolean bool, Boolean bool2, String str4, Boolean bool3) {
        Intrinsics.checkNotNullParameter(value, "value");
        Intrinsics.checkNotNullParameter(key, "key");
        return new GBExperimentResult(z, i, value, str, str2, key, str3, f, bool, bool2, str4, bool3);
    }

    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof GBExperimentResult)) {
            return false;
        }
        GBExperimentResult gBExperimentResult = (GBExperimentResult) obj;
        return this.inExperiment == gBExperimentResult.inExperiment && this.variationId == gBExperimentResult.variationId && Intrinsics.b(this.value, gBExperimentResult.value) && Intrinsics.b(this.hashAttribute, gBExperimentResult.hashAttribute) && Intrinsics.b(this.hashValue, gBExperimentResult.hashValue) && Intrinsics.b(this.key, gBExperimentResult.key) && Intrinsics.b(this.name, gBExperimentResult.name) && Intrinsics.b(this.bucket, gBExperimentResult.bucket) && Intrinsics.b(this.passthrough, gBExperimentResult.passthrough) && Intrinsics.b(this.hashUsed, gBExperimentResult.hashUsed) && Intrinsics.b(this.featureId, gBExperimentResult.featureId) && Intrinsics.b(this.stickyBucketUsed, gBExperimentResult.stickyBucketUsed);
    }

    @NotNull
    public final SerializableGBExperimentResult gbSerialize$GrowthBook_release() {
        String str = this.key;
        String str2 = this.name;
        Float f = this.bucket;
        Boolean bool = this.hashUsed;
        String str3 = this.hashValue;
        String str4 = this.featureId;
        Boolean bool2 = this.passthrough;
        return new SerializableGBExperimentResult(this.inExperiment, this.variationId, this.value.gbSerialize$GrowthBook_release(), this.hashAttribute, str3, str, str2, f, bool2, bool, str4, this.stickyBucketUsed);
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
    public final GBValue getValue() {
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
        return "GBExperimentResult(inExperiment=" + this.inExperiment + ", variationId=" + this.variationId + ", value=" + this.value + ", hashAttribute=" + this.hashAttribute + ", hashValue=" + this.hashValue + ", key=" + this.key + ", name=" + this.name + ", bucket=" + this.bucket + ", passthrough=" + this.passthrough + ", hashUsed=" + this.hashUsed + ", featureId=" + this.featureId + ", stickyBucketUsed=" + this.stickyBucketUsed + ')';
    }

    public /* synthetic */ GBExperimentResult(boolean z, int i, GBValue gBValue, String str, String str2, String str3, String str4, Float f, Boolean bool, Boolean bool2, String str5, Boolean bool3, int i2, DefaultConstructorMarker defaultConstructorMarker) {
        this((i2 & 1) != 0 ? false : z, (i2 & 2) != 0 ? 0 : i, gBValue, (i2 & 8) != 0 ? null : str, (i2 & 16) != 0 ? null : str2, (i2 & 32) != 0 ? "" : str3, (i2 & 64) != 0 ? null : str4, (i2 & 128) != 0 ? null : f, (i2 & 256) != 0 ? null : bool, (i2 & g.MAX_CONTENT_URL_LENGTH) != 0 ? null : bool2, (i2 & 1024) != 0 ? null : str5, (i2 & 2048) != 0 ? null : bool3);
    }
}
