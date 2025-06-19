package com.sdk.growthbook.model;

import androidx.compose.animation.d0;
import com.google.android.gms.ads.g;
import com.sdk.growthbook.serializable_model.SerializableGBExperiment;
import com.sdk.growthbook.utils.GBFilter;
import com.sdk.growthbook.utils.GBParentConditionInterface;
import com.sdk.growthbook.utils.GBVariationMeta;
import com.sdk.growthbook.utils.RangeSerializer;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import kotlin.Metadata;
import kotlin.Pair;
import kotlin.collections.C;
import kotlin.collections.K;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.serialization.f;
import kotlinx.serialization.json.d;
import kotlinx.serialization.json.k;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public final class GBExperiment {
    private Boolean active;
    private final Integer bucketVersion;
    private k condition;
    private Float coverage;
    private final Boolean disableStickyBucketing;
    private final String fallBackAttribute;
    private ArrayList<GBFilter> filters;
    private Integer force;
    private final String hashAttribute;
    private Integer hashVersion;

    @NotNull
    private final String key;
    private ArrayList<GBVariationMeta> meta;
    private final Integer minBucketVersion;
    private String name;
    private final d namespace;
    private final ArrayList<GBParentConditionInterface> parentConditions;
    private String phase;
    private List<Pair<Float, Float>> ranges;
    private String seed;

    @NotNull
    private final List<GBValue> variations;
    private List<Float> weights;

    /* JADX WARN: Multi-variable type inference failed */
    public GBExperiment(@NotNull String key, @NotNull List<? extends GBValue> variations, d dVar, String str, List<Float> list, Boolean bool, Float f, k kVar, ArrayList<GBParentConditionInterface> arrayList, Integer num, Integer num2, List<Pair<Float, Float>> list2, ArrayList<GBVariationMeta> arrayList2, ArrayList<GBFilter> arrayList3, String str2, String str3, String str4, String str5, Boolean bool2, Integer num3, Integer num4) {
        Intrinsics.checkNotNullParameter(key, "key");
        Intrinsics.checkNotNullParameter(variations, "variations");
        this.key = key;
        this.variations = variations;
        this.namespace = dVar;
        this.hashAttribute = str;
        this.weights = list;
        this.active = bool;
        this.coverage = f;
        this.condition = kVar;
        this.parentConditions = arrayList;
        this.force = num;
        this.hashVersion = num2;
        this.ranges = list2;
        this.meta = arrayList2;
        this.filters = arrayList3;
        this.seed = str2;
        this.name = str3;
        this.phase = str4;
        this.fallBackAttribute = str5;
        this.disableStickyBucketing = bool2;
        this.bucketVersion = num3;
        this.minBucketVersion = num4;
    }

    public static /* synthetic */ GBExperiment copy$default(GBExperiment gBExperiment, String str, List list, d dVar, String str2, List list2, Boolean bool, Float f, k kVar, ArrayList arrayList, Integer num, Integer num2, List list3, ArrayList arrayList2, ArrayList arrayList3, String str3, String str4, String str5, String str6, Boolean bool2, Integer num3, Integer num4, int i, Object obj) {
        Integer num5;
        Integer num6;
        String str7 = (i & 1) != 0 ? gBExperiment.key : str;
        List list4 = (i & 2) != 0 ? gBExperiment.variations : list;
        d dVar2 = (i & 4) != 0 ? gBExperiment.namespace : dVar;
        String str8 = (i & 8) != 0 ? gBExperiment.hashAttribute : str2;
        List list5 = (i & 16) != 0 ? gBExperiment.weights : list2;
        Boolean bool3 = (i & 32) != 0 ? gBExperiment.active : bool;
        Float f2 = (i & 64) != 0 ? gBExperiment.coverage : f;
        k kVar2 = (i & 128) != 0 ? gBExperiment.condition : kVar;
        ArrayList arrayList4 = (i & 256) != 0 ? gBExperiment.parentConditions : arrayList;
        Integer num7 = (i & g.MAX_CONTENT_URL_LENGTH) != 0 ? gBExperiment.force : num;
        Integer num8 = (i & 1024) != 0 ? gBExperiment.hashVersion : num2;
        List list6 = (i & 2048) != 0 ? gBExperiment.ranges : list3;
        ArrayList arrayList5 = (i & 4096) != 0 ? gBExperiment.meta : arrayList2;
        ArrayList arrayList6 = (i & 8192) != 0 ? gBExperiment.filters : arrayList3;
        String str9 = str7;
        String str10 = (i & 16384) != 0 ? gBExperiment.seed : str3;
        String str11 = (i & 32768) != 0 ? gBExperiment.name : str4;
        String str12 = (i & 65536) != 0 ? gBExperiment.phase : str5;
        String str13 = (i & 131072) != 0 ? gBExperiment.fallBackAttribute : str6;
        Boolean bool4 = (i & 262144) != 0 ? gBExperiment.disableStickyBucketing : bool2;
        Integer num9 = (i & 524288) != 0 ? gBExperiment.bucketVersion : num3;
        if ((i & 1048576) != 0) {
            num6 = num9;
            num5 = gBExperiment.minBucketVersion;
        } else {
            num5 = num4;
            num6 = num9;
        }
        return gBExperiment.copy(str9, list4, dVar2, str8, list5, bool3, f2, kVar2, arrayList4, num7, num8, list6, arrayList5, arrayList6, str10, str11, str12, str13, bool4, num6, num5);
    }

    @f(with = RangeSerializer.GBBucketRangeListSerializer.class)
    public static /* synthetic */ void getRanges$annotations() {
    }

    @NotNull
    public final String component1() {
        return this.key;
    }

    public final Integer component10() {
        return this.force;
    }

    public final Integer component11() {
        return this.hashVersion;
    }

    public final List<Pair<Float, Float>> component12() {
        return this.ranges;
    }

    public final ArrayList<GBVariationMeta> component13() {
        return this.meta;
    }

    public final ArrayList<GBFilter> component14() {
        return this.filters;
    }

    public final String component15() {
        return this.seed;
    }

    public final String component16() {
        return this.name;
    }

    public final String component17() {
        return this.phase;
    }

    public final String component18() {
        return this.fallBackAttribute;
    }

    public final Boolean component19() {
        return this.disableStickyBucketing;
    }

    @NotNull
    public final List<GBValue> component2() {
        return this.variations;
    }

    public final Integer component20() {
        return this.bucketVersion;
    }

    public final Integer component21() {
        return this.minBucketVersion;
    }

    public final d component3() {
        return this.namespace;
    }

    public final String component4() {
        return this.hashAttribute;
    }

    public final List<Float> component5() {
        return this.weights;
    }

    public final Boolean component6() {
        return this.active;
    }

    public final Float component7() {
        return this.coverage;
    }

    public final k component8() {
        return this.condition;
    }

    public final ArrayList<GBParentConditionInterface> component9() {
        return this.parentConditions;
    }

    @NotNull
    public final GBExperiment copy(@NotNull String key, @NotNull List<? extends GBValue> variations, d dVar, String str, List<Float> list, Boolean bool, Float f, k kVar, ArrayList<GBParentConditionInterface> arrayList, Integer num, Integer num2, List<Pair<Float, Float>> list2, ArrayList<GBVariationMeta> arrayList2, ArrayList<GBFilter> arrayList3, String str2, String str3, String str4, String str5, Boolean bool2, Integer num3, Integer num4) {
        Intrinsics.checkNotNullParameter(key, "key");
        Intrinsics.checkNotNullParameter(variations, "variations");
        return new GBExperiment(key, variations, dVar, str, list, bool, f, kVar, arrayList, num, num2, list2, arrayList2, arrayList3, str2, str3, str4, str5, bool2, num3, num4);
    }

    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof GBExperiment)) {
            return false;
        }
        GBExperiment gBExperiment = (GBExperiment) obj;
        return Intrinsics.b(this.key, gBExperiment.key) && Intrinsics.b(this.variations, gBExperiment.variations) && Intrinsics.b(this.namespace, gBExperiment.namespace) && Intrinsics.b(this.hashAttribute, gBExperiment.hashAttribute) && Intrinsics.b(this.weights, gBExperiment.weights) && Intrinsics.b(this.active, gBExperiment.active) && Intrinsics.b(this.coverage, gBExperiment.coverage) && Intrinsics.b(this.condition, gBExperiment.condition) && Intrinsics.b(this.parentConditions, gBExperiment.parentConditions) && Intrinsics.b(this.force, gBExperiment.force) && Intrinsics.b(this.hashVersion, gBExperiment.hashVersion) && Intrinsics.b(this.ranges, gBExperiment.ranges) && Intrinsics.b(this.meta, gBExperiment.meta) && Intrinsics.b(this.filters, gBExperiment.filters) && Intrinsics.b(this.seed, gBExperiment.seed) && Intrinsics.b(this.name, gBExperiment.name) && Intrinsics.b(this.phase, gBExperiment.phase) && Intrinsics.b(this.fallBackAttribute, gBExperiment.fallBackAttribute) && Intrinsics.b(this.disableStickyBucketing, gBExperiment.disableStickyBucketing) && Intrinsics.b(this.bucketVersion, gBExperiment.bucketVersion) && Intrinsics.b(this.minBucketVersion, gBExperiment.minBucketVersion);
    }

    @NotNull
    public final SerializableGBExperiment gbSerialize$GrowthBook_release() {
        String str = this.key;
        ArrayList<GBVariationMeta> arrayList = this.meta;
        String str2 = this.seed;
        String str3 = this.name;
        Integer num = this.force;
        String str4 = this.phase;
        Boolean bool = this.active;
        List<Pair<Float, Float>> list = this.ranges;
        ArrayList<GBFilter> arrayList2 = this.filters;
        List<Float> list2 = this.weights;
        Float f = this.coverage;
        k kVar = this.condition;
        d dVar = this.namespace;
        Integer num2 = this.hashVersion;
        Integer num3 = this.bucketVersion;
        String str5 = this.hashAttribute;
        Integer num4 = this.minBucketVersion;
        ArrayList<GBParentConditionInterface> arrayList3 = this.parentConditions;
        String str6 = this.fallBackAttribute;
        Boolean bool2 = this.disableStickyBucketing;
        List<GBValue> list3 = this.variations;
        ArrayList arrayList4 = new ArrayList(C.q(list3, 10));
        Iterator<T> it2 = list3.iterator();
        while (it2.hasNext()) {
            arrayList4.add(((GBValue) it2.next()).gbSerialize$GrowthBook_release());
        }
        return new SerializableGBExperiment(str, arrayList4, dVar, str5, list2, bool, f, kVar, arrayList3, num, num2, list, arrayList, arrayList2, str2, str3, str4, str6, bool2, num3, num4);
    }

    public final Boolean getActive() {
        return this.active;
    }

    public final Integer getBucketVersion() {
        return this.bucketVersion;
    }

    public final k getCondition() {
        return this.condition;
    }

    public final Float getCoverage() {
        return this.coverage;
    }

    public final Boolean getDisableStickyBucketing() {
        return this.disableStickyBucketing;
    }

    public final String getFallBackAttribute() {
        return this.fallBackAttribute;
    }

    public final ArrayList<GBFilter> getFilters() {
        return this.filters;
    }

    public final Integer getForce() {
        return this.force;
    }

    public final String getHashAttribute() {
        return this.hashAttribute;
    }

    public final Integer getHashVersion() {
        return this.hashVersion;
    }

    @NotNull
    public final String getKey() {
        return this.key;
    }

    public final ArrayList<GBVariationMeta> getMeta() {
        return this.meta;
    }

    public final Integer getMinBucketVersion() {
        return this.minBucketVersion;
    }

    public final String getName() {
        return this.name;
    }

    public final d getNamespace() {
        return this.namespace;
    }

    public final ArrayList<GBParentConditionInterface> getParentConditions() {
        return this.parentConditions;
    }

    public final String getPhase() {
        return this.phase;
    }

    public final List<Pair<Float, Float>> getRanges() {
        return this.ranges;
    }

    public final String getSeed() {
        return this.seed;
    }

    @NotNull
    public final List<GBValue> getVariations() {
        return this.variations;
    }

    public final List<Float> getWeights() {
        return this.weights;
    }

    public int hashCode() {
        int iF = d0.f(this.key.hashCode() * 31, 31, this.variations);
        d dVar = this.namespace;
        int iHashCode = (iF + (dVar == null ? 0 : dVar.a.hashCode())) * 31;
        String str = this.hashAttribute;
        int iHashCode2 = (iHashCode + (str == null ? 0 : str.hashCode())) * 31;
        List<Float> list = this.weights;
        int iHashCode3 = (iHashCode2 + (list == null ? 0 : list.hashCode())) * 31;
        Boolean bool = this.active;
        int iHashCode4 = (iHashCode3 + (bool == null ? 0 : bool.hashCode())) * 31;
        Float f = this.coverage;
        int iHashCode5 = (iHashCode4 + (f == null ? 0 : f.hashCode())) * 31;
        k kVar = this.condition;
        int iHashCode6 = (iHashCode5 + (kVar == null ? 0 : kVar.hashCode())) * 31;
        ArrayList<GBParentConditionInterface> arrayList = this.parentConditions;
        int iHashCode7 = (iHashCode6 + (arrayList == null ? 0 : arrayList.hashCode())) * 31;
        Integer num = this.force;
        int iHashCode8 = (iHashCode7 + (num == null ? 0 : num.hashCode())) * 31;
        Integer num2 = this.hashVersion;
        int iHashCode9 = (iHashCode8 + (num2 == null ? 0 : num2.hashCode())) * 31;
        List<Pair<Float, Float>> list2 = this.ranges;
        int iHashCode10 = (iHashCode9 + (list2 == null ? 0 : list2.hashCode())) * 31;
        ArrayList<GBVariationMeta> arrayList2 = this.meta;
        int iHashCode11 = (iHashCode10 + (arrayList2 == null ? 0 : arrayList2.hashCode())) * 31;
        ArrayList<GBFilter> arrayList3 = this.filters;
        int iHashCode12 = (iHashCode11 + (arrayList3 == null ? 0 : arrayList3.hashCode())) * 31;
        String str2 = this.seed;
        int iHashCode13 = (iHashCode12 + (str2 == null ? 0 : str2.hashCode())) * 31;
        String str3 = this.name;
        int iHashCode14 = (iHashCode13 + (str3 == null ? 0 : str3.hashCode())) * 31;
        String str4 = this.phase;
        int iHashCode15 = (iHashCode14 + (str4 == null ? 0 : str4.hashCode())) * 31;
        String str5 = this.fallBackAttribute;
        int iHashCode16 = (iHashCode15 + (str5 == null ? 0 : str5.hashCode())) * 31;
        Boolean bool2 = this.disableStickyBucketing;
        int iHashCode17 = (iHashCode16 + (bool2 == null ? 0 : bool2.hashCode())) * 31;
        Integer num3 = this.bucketVersion;
        int iHashCode18 = (iHashCode17 + (num3 == null ? 0 : num3.hashCode())) * 31;
        Integer num4 = this.minBucketVersion;
        return iHashCode18 + (num4 != null ? num4.hashCode() : 0);
    }

    public final void setActive(Boolean bool) {
        this.active = bool;
    }

    public final void setCondition(k kVar) {
        this.condition = kVar;
    }

    public final void setCoverage(Float f) {
        this.coverage = f;
    }

    public final void setFilters(ArrayList<GBFilter> arrayList) {
        this.filters = arrayList;
    }

    public final void setForce(Integer num) {
        this.force = num;
    }

    public final void setHashVersion(Integer num) {
        this.hashVersion = num;
    }

    public final void setMeta(ArrayList<GBVariationMeta> arrayList) {
        this.meta = arrayList;
    }

    public final void setName(String str) {
        this.name = str;
    }

    public final void setPhase(String str) {
        this.phase = str;
    }

    public final void setRanges(List<Pair<Float, Float>> list) {
        this.ranges = list;
    }

    public final void setSeed(String str) {
        this.seed = str;
    }

    public final void setWeights(List<Float> list) {
        this.weights = list;
    }

    @NotNull
    public String toString() {
        return "GBExperiment(key=" + this.key + ", variations=" + this.variations + ", namespace=" + this.namespace + ", hashAttribute=" + this.hashAttribute + ", weights=" + this.weights + ", active=" + this.active + ", coverage=" + this.coverage + ", condition=" + this.condition + ", parentConditions=" + this.parentConditions + ", force=" + this.force + ", hashVersion=" + this.hashVersion + ", ranges=" + this.ranges + ", meta=" + this.meta + ", filters=" + this.filters + ", seed=" + this.seed + ", name=" + this.name + ", phase=" + this.phase + ", fallBackAttribute=" + this.fallBackAttribute + ", disableStickyBucketing=" + this.disableStickyBucketing + ", bucketVersion=" + this.bucketVersion + ", minBucketVersion=" + this.minBucketVersion + ')';
    }

    public GBExperiment(String str, List list, d dVar, String str2, List list2, Boolean bool, Float f, k kVar, ArrayList arrayList, Integer num, Integer num2, List list3, ArrayList arrayList2, ArrayList arrayList3, String str3, String str4, String str5, String str6, Boolean bool2, Integer num3, Integer num4, int i, DefaultConstructorMarker defaultConstructorMarker) {
        this(str, (i & 2) != 0 ? K.a : list, (i & 4) != 0 ? null : dVar, (i & 8) != 0 ? null : str2, (i & 16) != 0 ? null : list2, (i & 32) != 0 ? Boolean.TRUE : bool, (i & 64) != 0 ? null : f, (i & 128) != 0 ? null : kVar, (i & 256) != 0 ? null : arrayList, (i & g.MAX_CONTENT_URL_LENGTH) != 0 ? null : num, (i & 1024) != 0 ? null : num2, (i & 2048) != 0 ? null : list3, (i & 4096) != 0 ? null : arrayList2, (i & 8192) != 0 ? null : arrayList3, (i & 16384) != 0 ? null : str3, (i & 32768) != 0 ? null : str4, (i & 65536) != 0 ? null : str5, (i & 131072) != 0 ? null : str6, (i & 262144) != 0 ? null : bool2, (i & 524288) != 0 ? null : num3, (i & 1048576) != 0 ? null : num4);
    }
}
