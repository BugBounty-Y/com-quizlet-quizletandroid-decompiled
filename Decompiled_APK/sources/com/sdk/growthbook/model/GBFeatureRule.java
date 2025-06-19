package com.sdk.growthbook.model;

import com.google.android.gms.ads.g;
import com.sdk.growthbook.serializable_model.SerializableGBFeatureRule;
import com.sdk.growthbook.utils.GBFilter;
import com.sdk.growthbook.utils.GBParentConditionInterface;
import com.sdk.growthbook.utils.GBTrackData;
import com.sdk.growthbook.utils.GBVariationMeta;
import com.sdk.growthbook.utils.OptionalProperty;
import com.sdk.growthbook.utils.RangeSerializer;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import kotlin.Metadata;
import kotlin.Pair;
import kotlin.collections.C;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.serialization.f;
import kotlinx.serialization.json.d;
import kotlinx.serialization.json.k;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public final class GBFeatureRule {
    private final Integer bucketVersion;
    private final k condition;
    private final Float coverage;
    private final Boolean disableStickyBucketing;
    private final String fallbackAttribute;
    private final ArrayList<GBFilter> filters;
    private final GBValue force;
    private final String hashAttribute;
    private final Integer hashVersion;
    private final String id;
    private final String key;
    private final ArrayList<GBVariationMeta> meta;
    private final Integer minBucketVersion;
    private final String name;
    private final d namespace;
    private final ArrayList<GBParentConditionInterface> parentConditions;
    private final String phase;
    private final Pair<Float, Float> range;
    private final List<Pair<Float, Float>> ranges;
    private final String seed;
    private final ArrayList<GBTrackData> tracks;
    private final List<GBValue> variations;
    private final List<Float> weights;

    public GBFeatureRule() {
        this(null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, 8388607, null);
    }

    public static /* synthetic */ GBFeatureRule copy$default(GBFeatureRule gBFeatureRule, String str, k kVar, ArrayList arrayList, Float f, GBValue gBValue, List list, String str2, List list2, d dVar, String str3, Integer num, Pair pair, List list3, ArrayList arrayList2, ArrayList arrayList3, String str4, String str5, String str6, String str7, Boolean bool, Integer num2, Integer num3, ArrayList arrayList4, int i, Object obj) {
        ArrayList arrayList5;
        Integer num4;
        String str8 = (i & 1) != 0 ? gBFeatureRule.id : str;
        k kVar2 = (i & 2) != 0 ? gBFeatureRule.condition : kVar;
        ArrayList arrayList6 = (i & 4) != 0 ? gBFeatureRule.parentConditions : arrayList;
        Float f2 = (i & 8) != 0 ? gBFeatureRule.coverage : f;
        GBValue gBValue2 = (i & 16) != 0 ? gBFeatureRule.force : gBValue;
        List list4 = (i & 32) != 0 ? gBFeatureRule.variations : list;
        String str9 = (i & 64) != 0 ? gBFeatureRule.key : str2;
        List list5 = (i & 128) != 0 ? gBFeatureRule.weights : list2;
        d dVar2 = (i & 256) != 0 ? gBFeatureRule.namespace : dVar;
        String str10 = (i & g.MAX_CONTENT_URL_LENGTH) != 0 ? gBFeatureRule.hashAttribute : str3;
        Integer num5 = (i & 1024) != 0 ? gBFeatureRule.hashVersion : num;
        Pair pair2 = (i & 2048) != 0 ? gBFeatureRule.range : pair;
        List list6 = (i & 4096) != 0 ? gBFeatureRule.ranges : list3;
        ArrayList arrayList7 = (i & 8192) != 0 ? gBFeatureRule.meta : arrayList2;
        String str11 = str8;
        ArrayList arrayList8 = (i & 16384) != 0 ? gBFeatureRule.filters : arrayList3;
        String str12 = (i & 32768) != 0 ? gBFeatureRule.seed : str4;
        String str13 = (i & 65536) != 0 ? gBFeatureRule.name : str5;
        String str14 = (i & 131072) != 0 ? gBFeatureRule.phase : str6;
        String str15 = (i & 262144) != 0 ? gBFeatureRule.fallbackAttribute : str7;
        Boolean bool2 = (i & 524288) != 0 ? gBFeatureRule.disableStickyBucketing : bool;
        Integer num6 = (i & 1048576) != 0 ? gBFeatureRule.bucketVersion : num2;
        Integer num7 = (i & 2097152) != 0 ? gBFeatureRule.minBucketVersion : num3;
        if ((i & 4194304) != 0) {
            num4 = num7;
            arrayList5 = gBFeatureRule.tracks;
        } else {
            arrayList5 = arrayList4;
            num4 = num7;
        }
        return gBFeatureRule.copy(str11, kVar2, arrayList6, f2, gBValue2, list4, str9, list5, dVar2, str10, num5, pair2, list6, arrayList7, arrayList8, str12, str13, str14, str15, bool2, num6, num4, arrayList5);
    }

    @f(with = RangeSerializer.GBBucketRangeSerializer.class)
    public static /* synthetic */ void getRange$annotations() {
    }

    @f(with = RangeSerializer.GBBucketRangeListSerializer.class)
    public static /* synthetic */ void getRanges$annotations() {
    }

    public final String component1() {
        return this.id;
    }

    public final String component10() {
        return this.hashAttribute;
    }

    public final Integer component11() {
        return this.hashVersion;
    }

    public final Pair<Float, Float> component12() {
        return this.range;
    }

    public final List<Pair<Float, Float>> component13() {
        return this.ranges;
    }

    public final ArrayList<GBVariationMeta> component14() {
        return this.meta;
    }

    public final ArrayList<GBFilter> component15() {
        return this.filters;
    }

    public final String component16() {
        return this.seed;
    }

    public final String component17() {
        return this.name;
    }

    public final String component18() {
        return this.phase;
    }

    public final String component19() {
        return this.fallbackAttribute;
    }

    public final k component2() {
        return this.condition;
    }

    public final Boolean component20() {
        return this.disableStickyBucketing;
    }

    public final Integer component21() {
        return this.bucketVersion;
    }

    public final Integer component22() {
        return this.minBucketVersion;
    }

    public final ArrayList<GBTrackData> component23() {
        return this.tracks;
    }

    public final ArrayList<GBParentConditionInterface> component3() {
        return this.parentConditions;
    }

    public final Float component4() {
        return this.coverage;
    }

    public final GBValue component5() {
        return this.force;
    }

    public final List<GBValue> component6() {
        return this.variations;
    }

    public final String component7() {
        return this.key;
    }

    public final List<Float> component8() {
        return this.weights;
    }

    public final d component9() {
        return this.namespace;
    }

    @NotNull
    public final GBFeatureRule copy(String str, k kVar, ArrayList<GBParentConditionInterface> arrayList, Float f, GBValue gBValue, List<? extends GBValue> list, String str2, List<Float> list2, d dVar, String str3, Integer num, Pair<Float, Float> pair, List<Pair<Float, Float>> list3, ArrayList<GBVariationMeta> arrayList2, ArrayList<GBFilter> arrayList3, String str4, String str5, String str6, String str7, Boolean bool, Integer num2, Integer num3, ArrayList<GBTrackData> arrayList4) {
        return new GBFeatureRule(str, kVar, arrayList, f, gBValue, list, str2, list2, dVar, str3, num, pair, list3, arrayList2, arrayList3, str4, str5, str6, str7, bool, num2, num3, arrayList4);
    }

    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof GBFeatureRule)) {
            return false;
        }
        GBFeatureRule gBFeatureRule = (GBFeatureRule) obj;
        return Intrinsics.b(this.id, gBFeatureRule.id) && Intrinsics.b(this.condition, gBFeatureRule.condition) && Intrinsics.b(this.parentConditions, gBFeatureRule.parentConditions) && Intrinsics.b(this.coverage, gBFeatureRule.coverage) && Intrinsics.b(this.force, gBFeatureRule.force) && Intrinsics.b(this.variations, gBFeatureRule.variations) && Intrinsics.b(this.key, gBFeatureRule.key) && Intrinsics.b(this.weights, gBFeatureRule.weights) && Intrinsics.b(this.namespace, gBFeatureRule.namespace) && Intrinsics.b(this.hashAttribute, gBFeatureRule.hashAttribute) && Intrinsics.b(this.hashVersion, gBFeatureRule.hashVersion) && Intrinsics.b(this.range, gBFeatureRule.range) && Intrinsics.b(this.ranges, gBFeatureRule.ranges) && Intrinsics.b(this.meta, gBFeatureRule.meta) && Intrinsics.b(this.filters, gBFeatureRule.filters) && Intrinsics.b(this.seed, gBFeatureRule.seed) && Intrinsics.b(this.name, gBFeatureRule.name) && Intrinsics.b(this.phase, gBFeatureRule.phase) && Intrinsics.b(this.fallbackAttribute, gBFeatureRule.fallbackAttribute) && Intrinsics.b(this.disableStickyBucketing, gBFeatureRule.disableStickyBucketing) && Intrinsics.b(this.bucketVersion, gBFeatureRule.bucketVersion) && Intrinsics.b(this.minBucketVersion, gBFeatureRule.minBucketVersion) && Intrinsics.b(this.tracks, gBFeatureRule.tracks);
    }

    @NotNull
    public final SerializableGBFeatureRule gbSerialize$GrowthBook_release() {
        ArrayList arrayList;
        String str;
        String str2 = this.id;
        k kVar = this.condition;
        ArrayList<GBParentConditionInterface> arrayList2 = this.parentConditions;
        Float f = this.coverage;
        GBValue gBValue = this.force;
        OptionalProperty present = gBValue == null ? OptionalProperty.NotPresent.INSTANCE : new OptionalProperty.Present(gBValue.gbSerialize$GrowthBook_release());
        List<GBValue> list = this.variations;
        if (list != null) {
            arrayList = new ArrayList(C.q(list, 10));
            Iterator<T> it2 = list.iterator();
            while (it2.hasNext()) {
                arrayList.add(((GBValue) it2.next()).gbSerialize$GrowthBook_release());
            }
        } else {
            arrayList = null;
        }
        String str3 = this.key;
        ArrayList arrayList3 = arrayList;
        List<Float> list2 = this.weights;
        d dVar = this.namespace;
        String str4 = this.hashAttribute;
        Integer num = this.hashVersion;
        Pair<Float, Float> pair = this.range;
        List<Pair<Float, Float>> list3 = this.ranges;
        ArrayList arrayList4 = null;
        ArrayList<GBVariationMeta> arrayList5 = this.meta;
        ArrayList<GBFilter> arrayList6 = this.filters;
        String str5 = this.seed;
        String str6 = this.name;
        String str7 = this.phase;
        String str8 = this.fallbackAttribute;
        Boolean bool = this.disableStickyBucketing;
        Integer num2 = this.bucketVersion;
        Integer num3 = this.minBucketVersion;
        ArrayList<GBTrackData> arrayList7 = this.tracks;
        if (arrayList7 != null) {
            str = str2;
            ArrayList arrayList8 = new ArrayList(C.q(arrayList7, 10));
            Iterator<T> it3 = arrayList7.iterator();
            while (it3.hasNext()) {
                arrayList8.add(((GBTrackData) it3.next()).gbSerialize$GrowthBook_release());
            }
            arrayList4 = new ArrayList(arrayList8);
        } else {
            str = str2;
        }
        return new SerializableGBFeatureRule(str, kVar, arrayList2, f, present, arrayList3, str3, list2, dVar, str4, num, pair, list3, arrayList5, arrayList6, str5, str6, str7, str8, bool, num2, num3, arrayList4);
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

    public final String getFallbackAttribute() {
        return this.fallbackAttribute;
    }

    public final ArrayList<GBFilter> getFilters() {
        return this.filters;
    }

    public final GBValue getForce() {
        return this.force;
    }

    public final String getHashAttribute() {
        return this.hashAttribute;
    }

    public final Integer getHashVersion() {
        return this.hashVersion;
    }

    public final String getId() {
        return this.id;
    }

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

    public final Pair<Float, Float> getRange() {
        return this.range;
    }

    public final List<Pair<Float, Float>> getRanges() {
        return this.ranges;
    }

    public final String getSeed() {
        return this.seed;
    }

    public final ArrayList<GBTrackData> getTracks() {
        return this.tracks;
    }

    public final List<GBValue> getVariations() {
        return this.variations;
    }

    public final List<Float> getWeights() {
        return this.weights;
    }

    public int hashCode() {
        String str = this.id;
        int iHashCode = (str == null ? 0 : str.hashCode()) * 31;
        k kVar = this.condition;
        int iHashCode2 = (iHashCode + (kVar == null ? 0 : kVar.hashCode())) * 31;
        ArrayList<GBParentConditionInterface> arrayList = this.parentConditions;
        int iHashCode3 = (iHashCode2 + (arrayList == null ? 0 : arrayList.hashCode())) * 31;
        Float f = this.coverage;
        int iHashCode4 = (iHashCode3 + (f == null ? 0 : f.hashCode())) * 31;
        GBValue gBValue = this.force;
        int iHashCode5 = (iHashCode4 + (gBValue == null ? 0 : gBValue.hashCode())) * 31;
        List<GBValue> list = this.variations;
        int iHashCode6 = (iHashCode5 + (list == null ? 0 : list.hashCode())) * 31;
        String str2 = this.key;
        int iHashCode7 = (iHashCode6 + (str2 == null ? 0 : str2.hashCode())) * 31;
        List<Float> list2 = this.weights;
        int iHashCode8 = (iHashCode7 + (list2 == null ? 0 : list2.hashCode())) * 31;
        d dVar = this.namespace;
        int iHashCode9 = (iHashCode8 + (dVar == null ? 0 : dVar.a.hashCode())) * 31;
        String str3 = this.hashAttribute;
        int iHashCode10 = (iHashCode9 + (str3 == null ? 0 : str3.hashCode())) * 31;
        Integer num = this.hashVersion;
        int iHashCode11 = (iHashCode10 + (num == null ? 0 : num.hashCode())) * 31;
        Pair<Float, Float> pair = this.range;
        int iHashCode12 = (iHashCode11 + (pair == null ? 0 : pair.hashCode())) * 31;
        List<Pair<Float, Float>> list3 = this.ranges;
        int iHashCode13 = (iHashCode12 + (list3 == null ? 0 : list3.hashCode())) * 31;
        ArrayList<GBVariationMeta> arrayList2 = this.meta;
        int iHashCode14 = (iHashCode13 + (arrayList2 == null ? 0 : arrayList2.hashCode())) * 31;
        ArrayList<GBFilter> arrayList3 = this.filters;
        int iHashCode15 = (iHashCode14 + (arrayList3 == null ? 0 : arrayList3.hashCode())) * 31;
        String str4 = this.seed;
        int iHashCode16 = (iHashCode15 + (str4 == null ? 0 : str4.hashCode())) * 31;
        String str5 = this.name;
        int iHashCode17 = (iHashCode16 + (str5 == null ? 0 : str5.hashCode())) * 31;
        String str6 = this.phase;
        int iHashCode18 = (iHashCode17 + (str6 == null ? 0 : str6.hashCode())) * 31;
        String str7 = this.fallbackAttribute;
        int iHashCode19 = (iHashCode18 + (str7 == null ? 0 : str7.hashCode())) * 31;
        Boolean bool = this.disableStickyBucketing;
        int iHashCode20 = (iHashCode19 + (bool == null ? 0 : bool.hashCode())) * 31;
        Integer num2 = this.bucketVersion;
        int iHashCode21 = (iHashCode20 + (num2 == null ? 0 : num2.hashCode())) * 31;
        Integer num3 = this.minBucketVersion;
        int iHashCode22 = (iHashCode21 + (num3 == null ? 0 : num3.hashCode())) * 31;
        ArrayList<GBTrackData> arrayList4 = this.tracks;
        return iHashCode22 + (arrayList4 != null ? arrayList4.hashCode() : 0);
    }

    @NotNull
    public String toString() {
        return "GBFeatureRule(id=" + this.id + ", condition=" + this.condition + ", parentConditions=" + this.parentConditions + ", coverage=" + this.coverage + ", force=" + this.force + ", variations=" + this.variations + ", key=" + this.key + ", weights=" + this.weights + ", namespace=" + this.namespace + ", hashAttribute=" + this.hashAttribute + ", hashVersion=" + this.hashVersion + ", range=" + this.range + ", ranges=" + this.ranges + ", meta=" + this.meta + ", filters=" + this.filters + ", seed=" + this.seed + ", name=" + this.name + ", phase=" + this.phase + ", fallbackAttribute=" + this.fallbackAttribute + ", disableStickyBucketing=" + this.disableStickyBucketing + ", bucketVersion=" + this.bucketVersion + ", minBucketVersion=" + this.minBucketVersion + ", tracks=" + this.tracks + ')';
    }

    /* JADX WARN: Multi-variable type inference failed */
    public GBFeatureRule(String str, k kVar, ArrayList<GBParentConditionInterface> arrayList, Float f, GBValue gBValue, List<? extends GBValue> list, String str2, List<Float> list2, d dVar, String str3, Integer num, Pair<Float, Float> pair, List<Pair<Float, Float>> list3, ArrayList<GBVariationMeta> arrayList2, ArrayList<GBFilter> arrayList3, String str4, String str5, String str6, String str7, Boolean bool, Integer num2, Integer num3, ArrayList<GBTrackData> arrayList4) {
        this.id = str;
        this.condition = kVar;
        this.parentConditions = arrayList;
        this.coverage = f;
        this.force = gBValue;
        this.variations = list;
        this.key = str2;
        this.weights = list2;
        this.namespace = dVar;
        this.hashAttribute = str3;
        this.hashVersion = num;
        this.range = pair;
        this.ranges = list3;
        this.meta = arrayList2;
        this.filters = arrayList3;
        this.seed = str4;
        this.name = str5;
        this.phase = str6;
        this.fallbackAttribute = str7;
        this.disableStickyBucketing = bool;
        this.bucketVersion = num2;
        this.minBucketVersion = num3;
        this.tracks = arrayList4;
    }

    public /* synthetic */ GBFeatureRule(String str, k kVar, ArrayList arrayList, Float f, GBValue gBValue, List list, String str2, List list2, d dVar, String str3, Integer num, Pair pair, List list3, ArrayList arrayList2, ArrayList arrayList3, String str4, String str5, String str6, String str7, Boolean bool, Integer num2, Integer num3, ArrayList arrayList4, int i, DefaultConstructorMarker defaultConstructorMarker) {
        this((i & 1) != 0 ? null : str, (i & 2) != 0 ? null : kVar, (i & 4) != 0 ? null : arrayList, (i & 8) != 0 ? null : f, (i & 16) != 0 ? null : gBValue, (i & 32) != 0 ? null : list, (i & 64) != 0 ? null : str2, (i & 128) != 0 ? null : list2, (i & 256) != 0 ? null : dVar, (i & g.MAX_CONTENT_URL_LENGTH) != 0 ? null : str3, (i & 1024) != 0 ? null : num, (i & 2048) != 0 ? null : pair, (i & 4096) != 0 ? null : list3, (i & 8192) != 0 ? null : arrayList2, (i & 16384) != 0 ? null : arrayList3, (i & 32768) != 0 ? null : str4, (i & 65536) != 0 ? null : str5, (i & 131072) != 0 ? null : str6, (i & 262144) != 0 ? null : str7, (i & 524288) != 0 ? null : bool, (i & 1048576) != 0 ? null : num2, (i & 2097152) != 0 ? null : num3, (i & 4194304) != 0 ? null : arrayList4);
    }
}
