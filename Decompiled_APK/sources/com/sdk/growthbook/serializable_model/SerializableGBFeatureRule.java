package com.sdk.growthbook.serializable_model;

import com.google.android.gms.ads.g;
import com.google.android.gms.internal.mlkit_vision_camera.R1;
import com.sdk.growthbook.utils.GBFilter;
import com.sdk.growthbook.utils.GBFilter$$serializer;
import com.sdk.growthbook.utils.GBParentConditionInterface;
import com.sdk.growthbook.utils.GBParentConditionInterface$$serializer;
import com.sdk.growthbook.utils.GBVariationMeta;
import com.sdk.growthbook.utils.GBVariationMeta$$serializer;
import com.sdk.growthbook.utils.OptionalProperty;
import com.sdk.growthbook.utils.OptionalPropertySerializer;
import com.sdk.growthbook.utils.RangeSerializer;
import java.util.ArrayList;
import java.util.List;
import kotlin.Metadata;
import kotlin.Pair;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.serialization.KSerializer;
import kotlinx.serialization.descriptors.SerialDescriptor;
import kotlinx.serialization.encoding.b;
import kotlinx.serialization.f;
import kotlinx.serialization.internal.C;
import kotlinx.serialization.internal.C5048d;
import kotlinx.serialization.internal.C5053g;
import kotlinx.serialization.internal.K;
import kotlinx.serialization.internal.l0;
import kotlinx.serialization.internal.q0;
import kotlinx.serialization.json.d;
import kotlinx.serialization.json.k;
import kotlinx.serialization.json.m;
import org.jetbrains.annotations.NotNull;

@f
@Metadata
/* loaded from: classes3.dex */
public final class SerializableGBFeatureRule {

    @NotNull
    private static final KSerializer[] $childSerializers;

    @NotNull
    public static final Companion Companion = new Companion(null);
    private final Integer bucketVersion;
    private final k condition;
    private final Float coverage;
    private final Boolean disableStickyBucketing;
    private final String fallbackAttribute;
    private final ArrayList<GBFilter> filters;

    @NotNull
    private final OptionalProperty<k> force;
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
    private final ArrayList<SerializableGBTrackData> tracks;
    private final List<k> variations;
    private final List<Float> weights;

    @Metadata
    public static final class Companion {
        private Companion() {
        }

        @NotNull
        public final KSerializer serializer() {
            return SerializableGBFeatureRule$$serializer.INSTANCE;
        }

        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }
    }

    static {
        C5048d c5048d = new C5048d(GBParentConditionInterface$$serializer.INSTANCE, 0);
        m mVar = m.a;
        $childSerializers = new KSerializer[]{null, null, c5048d, null, new OptionalPropertySerializer(R1.e(mVar)), new C5048d(mVar, 0), null, new C5048d(C.a, 0), null, null, null, null, null, new C5048d(GBVariationMeta$$serializer.INSTANCE, 0), new C5048d(GBFilter$$serializer.INSTANCE, 0), null, null, null, null, null, null, null, new C5048d(SerializableGBTrackData$$serializer.INSTANCE, 0)};
    }

    public SerializableGBFeatureRule() {
        this((String) null, (k) null, (ArrayList) null, (Float) null, (OptionalProperty) null, (List) null, (String) null, (List) null, (d) null, (String) null, (Integer) null, (Pair) null, (List) null, (ArrayList) null, (ArrayList) null, (String) null, (String) null, (String) null, (String) null, (Boolean) null, (Integer) null, (Integer) null, (ArrayList) null, 8388607, (DefaultConstructorMarker) null);
    }

    public static /* synthetic */ SerializableGBFeatureRule copy$default(SerializableGBFeatureRule serializableGBFeatureRule, String str, k kVar, ArrayList arrayList, Float f, OptionalProperty optionalProperty, List list, String str2, List list2, d dVar, String str3, Integer num, Pair pair, List list3, ArrayList arrayList2, ArrayList arrayList3, String str4, String str5, String str6, String str7, Boolean bool, Integer num2, Integer num3, ArrayList arrayList4, int i, Object obj) {
        ArrayList arrayList5;
        Integer num4;
        String str8 = (i & 1) != 0 ? serializableGBFeatureRule.id : str;
        k kVar2 = (i & 2) != 0 ? serializableGBFeatureRule.condition : kVar;
        ArrayList arrayList6 = (i & 4) != 0 ? serializableGBFeatureRule.parentConditions : arrayList;
        Float f2 = (i & 8) != 0 ? serializableGBFeatureRule.coverage : f;
        OptionalProperty optionalProperty2 = (i & 16) != 0 ? serializableGBFeatureRule.force : optionalProperty;
        List list4 = (i & 32) != 0 ? serializableGBFeatureRule.variations : list;
        String str9 = (i & 64) != 0 ? serializableGBFeatureRule.key : str2;
        List list5 = (i & 128) != 0 ? serializableGBFeatureRule.weights : list2;
        d dVar2 = (i & 256) != 0 ? serializableGBFeatureRule.namespace : dVar;
        String str10 = (i & g.MAX_CONTENT_URL_LENGTH) != 0 ? serializableGBFeatureRule.hashAttribute : str3;
        Integer num5 = (i & 1024) != 0 ? serializableGBFeatureRule.hashVersion : num;
        Pair pair2 = (i & 2048) != 0 ? serializableGBFeatureRule.range : pair;
        List list6 = (i & 4096) != 0 ? serializableGBFeatureRule.ranges : list3;
        ArrayList arrayList7 = (i & 8192) != 0 ? serializableGBFeatureRule.meta : arrayList2;
        String str11 = str8;
        ArrayList arrayList8 = (i & 16384) != 0 ? serializableGBFeatureRule.filters : arrayList3;
        String str12 = (i & 32768) != 0 ? serializableGBFeatureRule.seed : str4;
        String str13 = (i & 65536) != 0 ? serializableGBFeatureRule.name : str5;
        String str14 = (i & 131072) != 0 ? serializableGBFeatureRule.phase : str6;
        String str15 = (i & 262144) != 0 ? serializableGBFeatureRule.fallbackAttribute : str7;
        Boolean bool2 = (i & 524288) != 0 ? serializableGBFeatureRule.disableStickyBucketing : bool;
        Integer num6 = (i & 1048576) != 0 ? serializableGBFeatureRule.bucketVersion : num2;
        Integer num7 = (i & 2097152) != 0 ? serializableGBFeatureRule.minBucketVersion : num3;
        if ((i & 4194304) != 0) {
            num4 = num7;
            arrayList5 = serializableGBFeatureRule.tracks;
        } else {
            arrayList5 = arrayList4;
            num4 = num7;
        }
        return serializableGBFeatureRule.copy(str11, kVar2, arrayList6, f2, optionalProperty2, list4, str9, list5, dVar2, str10, num5, pair2, list6, arrayList7, arrayList8, str12, str13, str14, str15, bool2, num6, num4, arrayList5);
    }

    @f(with = OptionalPropertySerializer.class)
    public static /* synthetic */ void getForce$annotations() {
    }

    @f(with = RangeSerializer.GBBucketRangeSerializer.class)
    public static /* synthetic */ void getRange$annotations() {
    }

    @f(with = RangeSerializer.GBBucketRangeListSerializer.class)
    public static /* synthetic */ void getRanges$annotations() {
    }

    public static final /* synthetic */ void write$Self$GrowthBook_release(SerializableGBFeatureRule serializableGBFeatureRule, b bVar, SerialDescriptor serialDescriptor) {
        KSerializer[] kSerializerArr = $childSerializers;
        if (bVar.D(serialDescriptor) || serializableGBFeatureRule.id != null) {
            bVar.s(serialDescriptor, 0, q0.a, serializableGBFeatureRule.id);
        }
        if (bVar.D(serialDescriptor) || serializableGBFeatureRule.condition != null) {
            bVar.s(serialDescriptor, 1, m.a, serializableGBFeatureRule.condition);
        }
        if (bVar.D(serialDescriptor) || serializableGBFeatureRule.parentConditions != null) {
            bVar.s(serialDescriptor, 2, kSerializerArr[2], serializableGBFeatureRule.parentConditions);
        }
        if (bVar.D(serialDescriptor) || serializableGBFeatureRule.coverage != null) {
            bVar.s(serialDescriptor, 3, C.a, serializableGBFeatureRule.coverage);
        }
        if (bVar.D(serialDescriptor) || !Intrinsics.b(serializableGBFeatureRule.force, OptionalProperty.NotPresent.INSTANCE)) {
            bVar.i(serialDescriptor, 4, kSerializerArr[4], serializableGBFeatureRule.force);
        }
        if (bVar.D(serialDescriptor) || serializableGBFeatureRule.variations != null) {
            bVar.s(serialDescriptor, 5, kSerializerArr[5], serializableGBFeatureRule.variations);
        }
        if (bVar.D(serialDescriptor) || serializableGBFeatureRule.key != null) {
            bVar.s(serialDescriptor, 6, q0.a, serializableGBFeatureRule.key);
        }
        if (bVar.D(serialDescriptor) || serializableGBFeatureRule.weights != null) {
            bVar.s(serialDescriptor, 7, kSerializerArr[7], serializableGBFeatureRule.weights);
        }
        if (bVar.D(serialDescriptor) || serializableGBFeatureRule.namespace != null) {
            bVar.s(serialDescriptor, 8, kotlinx.serialization.json.f.a, serializableGBFeatureRule.namespace);
        }
        if (bVar.D(serialDescriptor) || serializableGBFeatureRule.hashAttribute != null) {
            bVar.s(serialDescriptor, 9, q0.a, serializableGBFeatureRule.hashAttribute);
        }
        if (bVar.D(serialDescriptor) || serializableGBFeatureRule.hashVersion != null) {
            bVar.s(serialDescriptor, 10, K.a, serializableGBFeatureRule.hashVersion);
        }
        if (bVar.D(serialDescriptor) || serializableGBFeatureRule.range != null) {
            bVar.s(serialDescriptor, 11, RangeSerializer.GBBucketRangeSerializer.INSTANCE, serializableGBFeatureRule.range);
        }
        if (bVar.D(serialDescriptor) || serializableGBFeatureRule.ranges != null) {
            bVar.s(serialDescriptor, 12, RangeSerializer.GBBucketRangeListSerializer.INSTANCE, serializableGBFeatureRule.ranges);
        }
        if (bVar.D(serialDescriptor) || serializableGBFeatureRule.meta != null) {
            bVar.s(serialDescriptor, 13, kSerializerArr[13], serializableGBFeatureRule.meta);
        }
        if (bVar.D(serialDescriptor) || serializableGBFeatureRule.filters != null) {
            bVar.s(serialDescriptor, 14, kSerializerArr[14], serializableGBFeatureRule.filters);
        }
        if (bVar.D(serialDescriptor) || serializableGBFeatureRule.seed != null) {
            bVar.s(serialDescriptor, 15, q0.a, serializableGBFeatureRule.seed);
        }
        if (bVar.D(serialDescriptor) || serializableGBFeatureRule.name != null) {
            bVar.s(serialDescriptor, 16, q0.a, serializableGBFeatureRule.name);
        }
        if (bVar.D(serialDescriptor) || serializableGBFeatureRule.phase != null) {
            bVar.s(serialDescriptor, 17, q0.a, serializableGBFeatureRule.phase);
        }
        if (bVar.D(serialDescriptor) || serializableGBFeatureRule.fallbackAttribute != null) {
            bVar.s(serialDescriptor, 18, q0.a, serializableGBFeatureRule.fallbackAttribute);
        }
        if (bVar.D(serialDescriptor) || serializableGBFeatureRule.disableStickyBucketing != null) {
            bVar.s(serialDescriptor, 19, C5053g.a, serializableGBFeatureRule.disableStickyBucketing);
        }
        if (bVar.D(serialDescriptor) || serializableGBFeatureRule.bucketVersion != null) {
            bVar.s(serialDescriptor, 20, K.a, serializableGBFeatureRule.bucketVersion);
        }
        if (bVar.D(serialDescriptor) || serializableGBFeatureRule.minBucketVersion != null) {
            bVar.s(serialDescriptor, 21, K.a, serializableGBFeatureRule.minBucketVersion);
        }
        if (!bVar.D(serialDescriptor) && serializableGBFeatureRule.tracks == null) {
            return;
        }
        bVar.s(serialDescriptor, 22, kSerializerArr[22], serializableGBFeatureRule.tracks);
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

    public final ArrayList<SerializableGBTrackData> component23() {
        return this.tracks;
    }

    public final ArrayList<GBParentConditionInterface> component3() {
        return this.parentConditions;
    }

    public final Float component4() {
        return this.coverage;
    }

    @NotNull
    public final OptionalProperty<k> component5() {
        return this.force;
    }

    public final List<k> component6() {
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
    public final SerializableGBFeatureRule copy(String str, k kVar, ArrayList<GBParentConditionInterface> arrayList, Float f, @NotNull OptionalProperty<? extends k> force, List<? extends k> list, String str2, List<Float> list2, d dVar, String str3, Integer num, Pair<Float, Float> pair, List<Pair<Float, Float>> list3, ArrayList<GBVariationMeta> arrayList2, ArrayList<GBFilter> arrayList3, String str4, String str5, String str6, String str7, Boolean bool, Integer num2, Integer num3, ArrayList<SerializableGBTrackData> arrayList4) {
        Intrinsics.checkNotNullParameter(force, "force");
        return new SerializableGBFeatureRule(str, kVar, arrayList, f, force, list, str2, list2, dVar, str3, num, pair, list3, arrayList2, arrayList3, str4, str5, str6, str7, bool, num2, num3, arrayList4);
    }

    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof SerializableGBFeatureRule)) {
            return false;
        }
        SerializableGBFeatureRule serializableGBFeatureRule = (SerializableGBFeatureRule) obj;
        return Intrinsics.b(this.id, serializableGBFeatureRule.id) && Intrinsics.b(this.condition, serializableGBFeatureRule.condition) && Intrinsics.b(this.parentConditions, serializableGBFeatureRule.parentConditions) && Intrinsics.b(this.coverage, serializableGBFeatureRule.coverage) && Intrinsics.b(this.force, serializableGBFeatureRule.force) && Intrinsics.b(this.variations, serializableGBFeatureRule.variations) && Intrinsics.b(this.key, serializableGBFeatureRule.key) && Intrinsics.b(this.weights, serializableGBFeatureRule.weights) && Intrinsics.b(this.namespace, serializableGBFeatureRule.namespace) && Intrinsics.b(this.hashAttribute, serializableGBFeatureRule.hashAttribute) && Intrinsics.b(this.hashVersion, serializableGBFeatureRule.hashVersion) && Intrinsics.b(this.range, serializableGBFeatureRule.range) && Intrinsics.b(this.ranges, serializableGBFeatureRule.ranges) && Intrinsics.b(this.meta, serializableGBFeatureRule.meta) && Intrinsics.b(this.filters, serializableGBFeatureRule.filters) && Intrinsics.b(this.seed, serializableGBFeatureRule.seed) && Intrinsics.b(this.name, serializableGBFeatureRule.name) && Intrinsics.b(this.phase, serializableGBFeatureRule.phase) && Intrinsics.b(this.fallbackAttribute, serializableGBFeatureRule.fallbackAttribute) && Intrinsics.b(this.disableStickyBucketing, serializableGBFeatureRule.disableStickyBucketing) && Intrinsics.b(this.bucketVersion, serializableGBFeatureRule.bucketVersion) && Intrinsics.b(this.minBucketVersion, serializableGBFeatureRule.minBucketVersion) && Intrinsics.b(this.tracks, serializableGBFeatureRule.tracks);
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

    @NotNull
    public final OptionalProperty<k> getForce() {
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

    public final ArrayList<SerializableGBTrackData> getTracks() {
        return this.tracks;
    }

    public final List<k> getVariations() {
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
        int iHashCode4 = (this.force.hashCode() + ((iHashCode3 + (f == null ? 0 : f.hashCode())) * 31)) * 31;
        List<k> list = this.variations;
        int iHashCode5 = (iHashCode4 + (list == null ? 0 : list.hashCode())) * 31;
        String str2 = this.key;
        int iHashCode6 = (iHashCode5 + (str2 == null ? 0 : str2.hashCode())) * 31;
        List<Float> list2 = this.weights;
        int iHashCode7 = (iHashCode6 + (list2 == null ? 0 : list2.hashCode())) * 31;
        d dVar = this.namespace;
        int iHashCode8 = (iHashCode7 + (dVar == null ? 0 : dVar.a.hashCode())) * 31;
        String str3 = this.hashAttribute;
        int iHashCode9 = (iHashCode8 + (str3 == null ? 0 : str3.hashCode())) * 31;
        Integer num = this.hashVersion;
        int iHashCode10 = (iHashCode9 + (num == null ? 0 : num.hashCode())) * 31;
        Pair<Float, Float> pair = this.range;
        int iHashCode11 = (iHashCode10 + (pair == null ? 0 : pair.hashCode())) * 31;
        List<Pair<Float, Float>> list3 = this.ranges;
        int iHashCode12 = (iHashCode11 + (list3 == null ? 0 : list3.hashCode())) * 31;
        ArrayList<GBVariationMeta> arrayList2 = this.meta;
        int iHashCode13 = (iHashCode12 + (arrayList2 == null ? 0 : arrayList2.hashCode())) * 31;
        ArrayList<GBFilter> arrayList3 = this.filters;
        int iHashCode14 = (iHashCode13 + (arrayList3 == null ? 0 : arrayList3.hashCode())) * 31;
        String str4 = this.seed;
        int iHashCode15 = (iHashCode14 + (str4 == null ? 0 : str4.hashCode())) * 31;
        String str5 = this.name;
        int iHashCode16 = (iHashCode15 + (str5 == null ? 0 : str5.hashCode())) * 31;
        String str6 = this.phase;
        int iHashCode17 = (iHashCode16 + (str6 == null ? 0 : str6.hashCode())) * 31;
        String str7 = this.fallbackAttribute;
        int iHashCode18 = (iHashCode17 + (str7 == null ? 0 : str7.hashCode())) * 31;
        Boolean bool = this.disableStickyBucketing;
        int iHashCode19 = (iHashCode18 + (bool == null ? 0 : bool.hashCode())) * 31;
        Integer num2 = this.bucketVersion;
        int iHashCode20 = (iHashCode19 + (num2 == null ? 0 : num2.hashCode())) * 31;
        Integer num3 = this.minBucketVersion;
        int iHashCode21 = (iHashCode20 + (num3 == null ? 0 : num3.hashCode())) * 31;
        ArrayList<SerializableGBTrackData> arrayList4 = this.tracks;
        return iHashCode21 + (arrayList4 != null ? arrayList4.hashCode() : 0);
    }

    @NotNull
    public String toString() {
        return "SerializableGBFeatureRule(id=" + this.id + ", condition=" + this.condition + ", parentConditions=" + this.parentConditions + ", coverage=" + this.coverage + ", force=" + this.force + ", variations=" + this.variations + ", key=" + this.key + ", weights=" + this.weights + ", namespace=" + this.namespace + ", hashAttribute=" + this.hashAttribute + ", hashVersion=" + this.hashVersion + ", range=" + this.range + ", ranges=" + this.ranges + ", meta=" + this.meta + ", filters=" + this.filters + ", seed=" + this.seed + ", name=" + this.name + ", phase=" + this.phase + ", fallbackAttribute=" + this.fallbackAttribute + ", disableStickyBucketing=" + this.disableStickyBucketing + ", bucketVersion=" + this.bucketVersion + ", minBucketVersion=" + this.minBucketVersion + ", tracks=" + this.tracks + ')';
    }

    public /* synthetic */ SerializableGBFeatureRule(int i, String str, k kVar, ArrayList arrayList, Float f, OptionalProperty optionalProperty, List list, String str2, List list2, d dVar, String str3, Integer num, Pair pair, List list3, ArrayList arrayList2, ArrayList arrayList3, String str4, String str5, String str6, String str7, Boolean bool, Integer num2, Integer num3, ArrayList arrayList4, l0 l0Var) {
        if ((i & 1) == 0) {
            this.id = null;
        } else {
            this.id = str;
        }
        if ((i & 2) == 0) {
            this.condition = null;
        } else {
            this.condition = kVar;
        }
        if ((i & 4) == 0) {
            this.parentConditions = null;
        } else {
            this.parentConditions = arrayList;
        }
        if ((i & 8) == 0) {
            this.coverage = null;
        } else {
            this.coverage = f;
        }
        if ((i & 16) == 0) {
            this.force = OptionalProperty.NotPresent.INSTANCE;
        } else {
            this.force = optionalProperty;
        }
        if ((i & 32) == 0) {
            this.variations = null;
        } else {
            this.variations = list;
        }
        if ((i & 64) == 0) {
            this.key = null;
        } else {
            this.key = str2;
        }
        if ((i & 128) == 0) {
            this.weights = null;
        } else {
            this.weights = list2;
        }
        if ((i & 256) == 0) {
            this.namespace = null;
        } else {
            this.namespace = dVar;
        }
        if ((i & g.MAX_CONTENT_URL_LENGTH) == 0) {
            this.hashAttribute = null;
        } else {
            this.hashAttribute = str3;
        }
        if ((i & 1024) == 0) {
            this.hashVersion = null;
        } else {
            this.hashVersion = num;
        }
        if ((i & 2048) == 0) {
            this.range = null;
        } else {
            this.range = pair;
        }
        if ((i & 4096) == 0) {
            this.ranges = null;
        } else {
            this.ranges = list3;
        }
        if ((i & 8192) == 0) {
            this.meta = null;
        } else {
            this.meta = arrayList2;
        }
        if ((i & 16384) == 0) {
            this.filters = null;
        } else {
            this.filters = arrayList3;
        }
        if ((32768 & i) == 0) {
            this.seed = null;
        } else {
            this.seed = str4;
        }
        if ((65536 & i) == 0) {
            this.name = null;
        } else {
            this.name = str5;
        }
        if ((131072 & i) == 0) {
            this.phase = null;
        } else {
            this.phase = str6;
        }
        if ((262144 & i) == 0) {
            this.fallbackAttribute = null;
        } else {
            this.fallbackAttribute = str7;
        }
        if ((524288 & i) == 0) {
            this.disableStickyBucketing = null;
        } else {
            this.disableStickyBucketing = bool;
        }
        if ((1048576 & i) == 0) {
            this.bucketVersion = null;
        } else {
            this.bucketVersion = num2;
        }
        if ((2097152 & i) == 0) {
            this.minBucketVersion = null;
        } else {
            this.minBucketVersion = num3;
        }
        if ((i & 4194304) == 0) {
            this.tracks = null;
        } else {
            this.tracks = arrayList4;
        }
    }

    /* JADX WARN: Multi-variable type inference failed */
    public SerializableGBFeatureRule(String str, k kVar, ArrayList<GBParentConditionInterface> arrayList, Float f, @NotNull OptionalProperty<? extends k> force, List<? extends k> list, String str2, List<Float> list2, d dVar, String str3, Integer num, Pair<Float, Float> pair, List<Pair<Float, Float>> list3, ArrayList<GBVariationMeta> arrayList2, ArrayList<GBFilter> arrayList3, String str4, String str5, String str6, String str7, Boolean bool, Integer num2, Integer num3, ArrayList<SerializableGBTrackData> arrayList4) {
        Intrinsics.checkNotNullParameter(force, "force");
        this.id = str;
        this.condition = kVar;
        this.parentConditions = arrayList;
        this.coverage = f;
        this.force = force;
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

    public /* synthetic */ SerializableGBFeatureRule(String str, k kVar, ArrayList arrayList, Float f, OptionalProperty optionalProperty, List list, String str2, List list2, d dVar, String str3, Integer num, Pair pair, List list3, ArrayList arrayList2, ArrayList arrayList3, String str4, String str5, String str6, String str7, Boolean bool, Integer num2, Integer num3, ArrayList arrayList4, int i, DefaultConstructorMarker defaultConstructorMarker) {
        this((i & 1) != 0 ? null : str, (i & 2) != 0 ? null : kVar, (i & 4) != 0 ? null : arrayList, (i & 8) != 0 ? null : f, (i & 16) != 0 ? OptionalProperty.NotPresent.INSTANCE : optionalProperty, (i & 32) != 0 ? null : list, (i & 64) != 0 ? null : str2, (i & 128) != 0 ? null : list2, (i & 256) != 0 ? null : dVar, (i & g.MAX_CONTENT_URL_LENGTH) != 0 ? null : str3, (i & 1024) != 0 ? null : num, (i & 2048) != 0 ? null : pair, (i & 4096) != 0 ? null : list3, (i & 8192) != 0 ? null : arrayList2, (i & 16384) != 0 ? null : arrayList3, (i & 32768) != 0 ? null : str4, (i & 65536) != 0 ? null : str5, (i & 131072) != 0 ? null : str6, (i & 262144) != 0 ? null : str7, (i & 524288) != 0 ? null : bool, (i & 1048576) != 0 ? null : num2, (i & 2097152) != 0 ? null : num3, (i & 4194304) != 0 ? null : arrayList4);
    }
}
